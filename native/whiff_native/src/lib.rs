//! Rustler NIF boundary for the Elixir `whiff` package.
//!
//! Returns UTF-8 JSON report bytes. Elixir decodes them with Jason (string keys).
//! Extraction runs on the DirtyCpu scheduler: after the file is opened, parsing
//! and hashing dominate.
//!
//! Every NIF returns tagged data and never raises: invalid input, upstream
//! errors, and panics all become `{:error, reason, message}`.

use std::any::Any;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rustler::{Binary, Encoder, Env, NewBinary, Term};
use serde::Deserialize;
use serde_json::{Map, Value};
use whiff::{Engine, Error as WhiffError, Hashes, Limits, Privacy, Profile};

mod atoms {
    rustler::atoms! {
        ok,
        error,
        enoent,
        eacces,
        native_error,
        invalid_option,
        invalid_report,
        unsupported_input,
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeOptions {
    #[serde(default)]
    profile: Option<String>,
    #[serde(default)]
    hashes: Option<HashesOpt>,
    #[serde(default)]
    privacy: Option<String>,
    #[serde(default)]
    only: Option<Vec<String>>,
    #[serde(default)]
    skip: Option<Vec<String>>,
    #[serde(default)]
    format: Option<String>,
    #[serde(default)]
    provenance: Option<bool>,
    #[serde(default)]
    limits: Option<LimitsOpt>,
    #[serde(default)]
    tokens: Option<usize>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum HashesOpt {
    Named(String),
    List(Vec<String>),
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct LimitsOpt {
    max_read_bytes: Option<u64>,
    max_decompressed_bytes: Option<u64>,
    max_depth: Option<u32>,
    max_children: Option<u32>,
    file_timeout_ms: Option<u64>,
    extractor_timeout_ms: Option<u64>,
    max_text_bytes: Option<u64>,
    hash_max_bytes: Option<u64>,
    max_parse_bytes: Option<u64>,
}

/// Upper caps for user-supplied limits. `Whiff.Options` mirrors these values;
/// a test compares both through `native_version/0`.
const LIMIT_CAPS: &[(&str, u64)] = &[
    ("max_read_bytes", 4 * 1024 * 1024 * 1024),
    ("max_decompressed_bytes", 4 * 1024 * 1024 * 1024),
    ("max_depth", 8),
    ("max_children", 500),
    ("file_timeout_ms", 600_000),
    ("extractor_timeout_ms", 600_000),
    ("max_text_bytes", 64 * 1024 * 1024),
    ("hash_max_bytes", 4 * 1024 * 1024 * 1024),
    ("max_parse_bytes", 256 * 1024 * 1024),
];

/// Limits where zero has no useful meaning upstream and is rejected.
const NONZERO_LIMITS: &[&str] = &[
    "max_read_bytes",
    "max_decompressed_bytes",
    "file_timeout_ms",
    "extractor_timeout_ms",
];

const DEFAULT_TOKENS: usize = 800;
const MAX_TOKENS: usize = 100_000;

/// Error classification. Kept as a plain enum (not `rustler::Atom`) so pure
/// helpers work in `cargo test`, where atoms are not initialised.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reason {
    Enoent,
    Eacces,
    NativeError,
    InvalidOption,
    InvalidReport,
    UnsupportedInput,
}

impl Reason {
    fn atom(self) -> rustler::Atom {
        match self {
            Reason::Enoent => atoms::enoent(),
            Reason::Eacces => atoms::eacces(),
            Reason::NativeError => atoms::native_error(),
            Reason::InvalidOption => atoms::invalid_option(),
            Reason::InvalidReport => atoms::invalid_report(),
            Reason::UnsupportedInput => atoms::unsupported_input(),
        }
    }
}

type NifError = (Reason, String);

fn invalid(msg: impl Into<String>) -> NifError {
    (Reason::InvalidOption, msg.into())
}

fn parse_options(json: &str) -> Result<NativeOptions, NifError> {
    if json.trim().is_empty() {
        return Ok(NativeOptions::default());
    }
    serde_json::from_str(json).map_err(|e| invalid(format!("invalid options json: {e}")))
}

fn hashes_from(opt: &HashesOpt) -> Result<Hashes, NifError> {
    match opt {
        // Hashes is #[non_exhaustive] since whiff 0.8: use constructors.
        HashesOpt::Named(name) => match name.as_str() {
            "all" => Ok(Hashes::default()),
            "none" => Ok(Hashes::NONE),
            other => Err(invalid(format!("invalid hashes `{other}`"))),
        },
        HashesOpt::List(list) => {
            let mut h = Hashes::NONE;
            for item in list {
                match item.as_str() {
                    "sha256" => h.sha256 = true,
                    "blake3" => h.blake3 = true,
                    other => return Err(invalid(format!("invalid hash `{other}`"))),
                }
            }
            Ok(h)
        }
    }
}

fn checked(name: &str, value: u64) -> Result<u64, NifError> {
    if value == 0 && NONZERO_LIMITS.contains(&name) {
        return Err(invalid(format!("{name} must be greater than 0")));
    }
    let cap = LIMIT_CAPS
        .iter()
        .find(|(key, _)| *key == name)
        .map(|(_, cap)| *cap)
        .unwrap_or(u64::MAX);
    if value > cap {
        return Err(invalid(format!("{name} exceeds cap {cap}")));
    }
    Ok(value)
}

fn checked_u32(name: &str, value: u32) -> Result<u32, NifError> {
    checked(name, u64::from(value)).map(|_| value)
}

fn apply_limits(mut base: Limits, opt: &LimitsOpt) -> Result<Limits, NifError> {
    if let Some(n) = opt.max_read_bytes {
        base.max_read_bytes = checked("max_read_bytes", n)?;
    }
    if let Some(n) = opt.max_decompressed_bytes {
        base.max_decompressed_bytes = checked("max_decompressed_bytes", n)?;
    }
    if let Some(n) = opt.max_depth {
        base.max_depth = checked_u32("max_depth", n)?;
    }
    if let Some(n) = opt.max_children {
        base.max_children = checked_u32("max_children", n)?;
    }
    if let Some(ms) = opt.file_timeout_ms {
        base.file_timeout = Some(Duration::from_millis(checked("file_timeout_ms", ms)?));
    }
    if let Some(ms) = opt.extractor_timeout_ms {
        base.extractor_timeout = Some(Duration::from_millis(checked("extractor_timeout_ms", ms)?));
    }
    if let Some(n) = opt.max_text_bytes {
        let n = checked("max_text_bytes", n)?;
        base.max_text_bytes =
            usize::try_from(n).map_err(|_| invalid("max_text_bytes too large"))?;
    }
    if let Some(n) = opt.hash_max_bytes {
        base.hash_max_bytes = checked("hash_max_bytes", n)?;
    }
    if let Some(n) = opt.max_parse_bytes {
        base.max_parse_bytes = checked("max_parse_bytes", n)?;
    }
    Ok(base)
}

fn build_engine(opts: &NativeOptions) -> Result<Engine, NifError> {
    let profile: Option<Profile> = opts
        .profile
        .as_deref()
        .map(|p| p.parse().map_err(|e: String| invalid(e)))
        .transpose()?;

    let mut builder = Engine::builder();

    if let Some(p) = profile {
        builder = builder.profile(p);
    }
    if let Some(ref h) = opts.hashes {
        builder = builder.hashes(hashes_from(h)?);
    }
    if let Some(ref p) = opts.privacy {
        let privacy: Privacy = p.parse().map_err(|e: String| invalid(e))?;
        builder = builder.privacy(privacy);
    }
    if let Some(ref only) = opts.only {
        builder = builder.only(only.clone());
    }
    if let Some(ref skip) = opts.skip {
        builder = builder.skip(skip.clone());
    }
    if let Some(ref format) = opts.format {
        builder = builder.format(format.clone());
    }
    if let Some(prov) = opts.provenance {
        builder = builder.provenance(prov);
    }
    if let Some(ref lim) = opts.limits {
        // Setting a profile resets limits, so start from the profile's limits.
        let limits = apply_limits(profile.unwrap_or_default().limits(), lim)?;
        builder = builder.limits(limits);
    }
    Ok(builder.build())
}

fn tokens_from(opts: &NativeOptions) -> Result<usize, NifError> {
    let tokens = opts.tokens.unwrap_or(DEFAULT_TOKENS);
    if tokens == 0 || tokens > MAX_TOKENS {
        return Err(invalid(format!("tokens must be 1..{MAX_TOKENS}")));
    }
    Ok(tokens)
}

/// Build a filesystem path from raw BEAM bytes. Unix paths are arbitrary
/// bytes; Windows paths must be valid UTF-8.
fn path_from_bytes(bytes: &[u8]) -> Result<PathBuf, NifError> {
    if bytes.is_empty() {
        return Err((Reason::UnsupportedInput, "path must not be empty".into()));
    }
    if bytes.contains(&0) {
        return Err((
            Reason::UnsupportedInput,
            "path must not contain NUL bytes".into(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        Ok(PathBuf::from(std::ffi::OsStr::from_bytes(bytes)))
    }
    #[cfg(not(unix))]
    {
        std::str::from_utf8(bytes)
            .map(PathBuf::from)
            .map_err(|_| (Reason::UnsupportedInput, "path is not valid UTF-8".into()))
    }
}

/// Upstream takes the display name as `&str`; invalid UTF-8 is replaced
/// lossily because the name only drives detection and `source.name`.
fn name_from_bytes(bytes: Option<Binary>) -> Option<String> {
    bytes.map(|b| String::from_utf8_lossy(b.as_slice()).into_owned())
}

fn io_error(err: WhiffError) -> NifError {
    match err {
        WhiffError::Io { path, source } => {
            let reason = match source.kind() {
                std::io::ErrorKind::NotFound => Reason::Enoent,
                std::io::ErrorKind::PermissionDenied => Reason::Eacces,
                _ => Reason::NativeError,
            };
            (reason, format!("{}: {source}", path.display()))
        }
        // Error is #[non_exhaustive] since whiff 0.8.
        other => (Reason::NativeError, other.to_string()),
    }
}

fn to_json(value: &impl serde::Serialize) -> Result<Vec<u8>, NifError> {
    serde_json::to_vec(value).map_err(|e| (Reason::InvalidReport, format!("serialize failed: {e}")))
}

fn panic_message(payload: &(dyn Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "unknown panic".to_string()
    }
}

/// Run `work`, converting errors and panics into `{:error, reason, message}`
/// and successful JSON into `{:ok, binary}`.
fn guarded<'a>(env: Env<'a>, work: impl FnOnce() -> Result<Vec<u8>, NifError>) -> Term<'a> {
    let outcome = catch_unwind(AssertUnwindSafe(work)).unwrap_or_else(|payload| {
        Err((
            Reason::NativeError,
            format!("native panic: {}", panic_message(payload.as_ref())),
        ))
    });

    match outcome {
        Ok(bytes) => {
            let mut bin = NewBinary::new(env, bytes.len());
            bin.as_mut_slice().copy_from_slice(&bytes);
            (atoms::ok(), Term::from(bin)).encode(env)
        }
        Err((reason, message)) => (atoms::error(), reason.atom(), message).encode(env),
    }
}

#[rustler::nif(schedule = "DirtyCpu")]
fn extract_path<'a>(env: Env<'a>, path: Binary<'a>, options_json: String) -> Term<'a> {
    guarded(env, || {
        let opts = parse_options(&options_json)?;
        let path = path_from_bytes(path.as_slice())?;
        let engine = build_engine(&opts)?;
        let report = engine.extract_path(&path).map_err(io_error)?;
        to_json(&report)
    })
}

#[rustler::nif(schedule = "DirtyCpu")]
fn extract_bytes<'a>(
    env: Env<'a>,
    data: Binary<'a>,
    name: Option<Binary<'a>>,
    options_json: String,
) -> Term<'a> {
    guarded(env, || {
        let opts = parse_options(&options_json)?;
        let engine = build_engine(&opts)?;
        let name = name_from_bytes(name);
        // One copy: BEAM binary -> Arc<[u8]>.
        let bytes: Arc<[u8]> = Arc::from(data.as_slice());
        to_json(&engine.extract_bytes(name.as_deref(), bytes))
    })
}

#[rustler::nif(schedule = "DirtyCpu")]
fn llm_path<'a>(env: Env<'a>, path: Binary<'a>, options_json: String) -> Term<'a> {
    guarded(env, || {
        let opts = parse_options(&options_json)?;
        let tokens = tokens_from(&opts)?;
        let path = path_from_bytes(path.as_slice())?;
        let engine = build_engine(&opts)?;
        let report = engine.extract_path(&path).map_err(io_error)?;
        to_json(&report.llm_view(tokens))
    })
}

#[rustler::nif]
fn native_version<'a>(env: Env<'a>) -> Term<'a> {
    guarded(env, || to_json(&version_info()))
}

fn version_info() -> Value {
    let mut caps = Map::new();
    for (key, cap) in LIMIT_CAPS {
        caps.insert((*key).into(), Value::from(*cap));
    }

    let mut map = Map::new();
    map.insert(
        "whiff".into(),
        Value::String(env!("CARGO_PKG_VERSION").into()),
    );
    map.insert(
        "crate".into(),
        Value::String(env!("WHIFF_CRATE_VERSION").into()),
    );
    map.insert("schema".into(), Value::String(whiff::SCHEMA.into()));
    map.insert(
        "features".into(),
        Value::Array(
            whiff::enabled_features()
                .into_iter()
                .map(|f| Value::String(f.into()))
                .collect(),
        ),
    );
    map.insert("limit_caps".into(), Value::Object(caps));
    Value::Object(map)
}

rustler::init!("Elixir.Whiff.Native");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_options_parse_to_defaults() {
        let opts = parse_options("").expect("defaults");
        assert!(opts.profile.is_none());
        assert!(build_engine(&opts).is_ok());
    }

    #[test]
    fn unknown_option_keys_are_rejected() {
        assert!(parse_options(r#"{"nope": 1}"#).is_err());
        assert!(parse_options(r#"{"limits": {"nope": 1}}"#).is_err());
    }

    #[test]
    fn hashes_named_and_list() {
        let none = hashes_from(&HashesOpt::Named("none".into())).expect("none");
        assert!(!none.sha256 && !none.blake3);
        let list = hashes_from(&HashesOpt::List(vec!["sha256".into()])).expect("list");
        assert!(list.sha256 && !list.blake3);
        assert!(hashes_from(&HashesOpt::Named("md5".into())).is_err());
        assert!(hashes_from(&HashesOpt::List(vec!["md5".into()])).is_err());
    }

    #[test]
    fn limits_respect_caps_and_nonzero_rules() {
        let base = Profile::default().limits();
        let ok = LimitsOpt {
            max_depth: Some(0),
            hash_max_bytes: Some(0),
            ..Default::default()
        };
        assert!(apply_limits(base.clone(), &ok).is_ok());

        let zero_timeout = LimitsOpt {
            file_timeout_ms: Some(0),
            ..Default::default()
        };
        assert!(apply_limits(base.clone(), &zero_timeout).is_err());

        let over = LimitsOpt {
            max_parse_bytes: Some(u64::MAX),
            ..Default::default()
        };
        assert!(apply_limits(base, &over).is_err());
    }

    #[test]
    fn invalid_profile_and_privacy_are_errors() {
        let bad_profile = parse_options(r#"{"profile": "turbo"}"#).expect("parse");
        assert!(build_engine(&bad_profile).is_err());
        let bad_privacy = parse_options(r#"{"privacy": "maybe"}"#).expect("parse");
        assert!(build_engine(&bad_privacy).is_err());
    }

    #[test]
    fn tokens_bounds() {
        let zero = parse_options(r#"{"tokens": 0}"#).expect("parse");
        assert!(tokens_from(&zero).is_err());
        let fine = parse_options(r#"{"tokens": 200}"#).expect("parse");
        assert_eq!(tokens_from(&fine).expect("tokens"), 200);
    }

    #[test]
    fn path_bytes_validation() {
        assert!(path_from_bytes(b"").is_err());
        assert!(path_from_bytes(b"a\0b").is_err());
        assert!(path_from_bytes(b"plain.txt").is_ok());
        #[cfg(unix)]
        assert!(path_from_bytes(&[b'x', 0xFF]).is_ok());
    }

    #[test]
    fn panic_payloads_are_described() {
        let payload = catch_unwind(|| panic!("boom")).expect_err("panics");
        assert_eq!(panic_message(payload.as_ref()), "boom");
    }

    #[test]
    fn version_info_reports_locked_crate_version() {
        let info = version_info();
        assert_ne!(info["crate"], "unknown");
        assert_eq!(info["schema"], whiff::SCHEMA);
        assert_eq!(info["limit_caps"]["max_depth"], 8);
    }
}
