//! Rustler NIF boundary for the Elixir `whiff` package.
//!
//! Returns UTF-8 JSON report bytes. Elixir decodes with Jason (string keys).
//! Heavy work runs on the DirtyCpu scheduler — parsing/hashing dominates after I/O.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use rustler::{Binary, Encoder, Env, Error as RustlerError, NewBinary, NifResult, Term};
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
    }
}

#[derive(Debug, Default, Deserialize)]
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
struct LimitsOpt {
    max_read_bytes: Option<u64>,
    max_decompressed_bytes: Option<u64>,
    max_depth: Option<u32>,
    max_children: Option<u32>,
    file_timeout_ms: Option<u64>,
    extractor_timeout_ms: Option<u64>,
    max_text_bytes: Option<usize>,
    hash_max_bytes: Option<u64>,
    max_parse_bytes: Option<u64>,
}

const MAX_READ_BYTES_CAP: u64 = 4 * 1024 * 1024 * 1024;
const MAX_DEPTH_CAP: u32 = 8;
const MAX_CHILDREN_CAP: u32 = 500;
const MAX_FILE_TIMEOUT_MS: u64 = 600_000;
const MAX_TOKENS: usize = 100_000;

fn parse_options(json: &str) -> Result<NativeOptions, String> {
    if json.trim().is_empty() {
        return Ok(NativeOptions::default());
    }
    serde_json::from_str(json).map_err(|e| format!("invalid options json: {e}"))
}

fn profile_from(s: &str) -> Result<Profile, String> {
    s.parse()
}

fn privacy_from(s: &str) -> Result<Privacy, String> {
    s.parse()
}

fn hashes_from(opt: HashesOpt) -> Result<Hashes, String> {
    match opt {
        HashesOpt::Named(name) => match name.as_str() {
            // Hashes is #[non_exhaustive] since whiff 0.8 — use constructors.
            "all" => Ok(Hashes::default()),
            "none" => Ok(Hashes::NONE),
            other => Err(format!("invalid hashes `{other}`")),
        },
        HashesOpt::List(list) => {
            let mut h = Hashes::NONE;
            for item in list {
                match item.as_str() {
                    "sha256" => h.sha256 = true,
                    "blake3" => h.blake3 = true,
                    other => return Err(format!("invalid hash `{other}`")),
                }
            }
            Ok(h)
        }
    }
}

fn apply_limits(mut base: Limits, opt: LimitsOpt) -> Result<Limits, String> {
    if let Some(n) = opt.max_read_bytes {
        if n > MAX_READ_BYTES_CAP {
            return Err(format!("max_read_bytes exceeds cap {MAX_READ_BYTES_CAP}"));
        }
        base.max_read_bytes = n;
    }
    if let Some(n) = opt.max_decompressed_bytes {
        if n > MAX_READ_BYTES_CAP {
            return Err(format!(
                "max_decompressed_bytes exceeds cap {MAX_READ_BYTES_CAP}"
            ));
        }
        base.max_decompressed_bytes = n;
    }
    if let Some(n) = opt.max_depth {
        if n > MAX_DEPTH_CAP {
            return Err(format!("max_depth exceeds cap {MAX_DEPTH_CAP}"));
        }
        base.max_depth = n;
    }
    if let Some(n) = opt.max_children {
        if n > MAX_CHILDREN_CAP {
            return Err(format!("max_children exceeds cap {MAX_CHILDREN_CAP}"));
        }
        base.max_children = n;
    }
    if let Some(ms) = opt.file_timeout_ms {
        if ms > MAX_FILE_TIMEOUT_MS {
            return Err(format!("file_timeout_ms exceeds cap {MAX_FILE_TIMEOUT_MS}"));
        }
        base.file_timeout = Some(Duration::from_millis(ms));
    }
    if let Some(ms) = opt.extractor_timeout_ms {
        if ms > MAX_FILE_TIMEOUT_MS {
            return Err(format!(
                "extractor_timeout_ms exceeds cap {MAX_FILE_TIMEOUT_MS}"
            ));
        }
        base.extractor_timeout = Some(Duration::from_millis(ms));
    }
    if let Some(n) = opt.max_text_bytes {
        base.max_text_bytes = n;
    }
    if let Some(n) = opt.hash_max_bytes {
        base.hash_max_bytes = n;
    }
    if let Some(n) = opt.max_parse_bytes {
        base.max_parse_bytes = n;
    }
    Ok(base)
}

fn build_engine(opts: &NativeOptions) -> Result<Engine, String> {
    let mut builder = Engine::builder();
    let mut limits_set = false;

    if let Some(ref p) = opts.profile {
        builder = builder.profile(profile_from(p)?);
    }
    if let Some(ref h) = opts.hashes {
        builder = builder.hashes(hashes_from(h.clone())?);
    }
    if let Some(ref p) = opts.privacy {
        builder = builder.privacy(privacy_from(p)?);
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
        let profile = opts
            .profile
            .as_deref()
            .map(profile_from)
            .transpose()?
            .unwrap_or_default();
        let limits = apply_limits(profile.limits(), lim.clone())?;
        builder = builder.limits(limits);
        limits_set = true;
    }
    let _ = limits_set;
    Ok(builder.build())
}

fn map_io_error<'a>(env: Env<'a>, err: WhiffError) -> Term<'a> {
    match err {
        WhiffError::Io { path, source } => {
            let reason = match source.kind() {
                std::io::ErrorKind::NotFound => atoms::enoent(),
                std::io::ErrorKind::PermissionDenied => atoms::eacces(),
                _ => atoms::native_error(),
            };
            let msg = format!("{}: {source}", path.display());
            (atoms::error(), reason, msg).encode(env)
        }
        // Error is #[non_exhaustive] since whiff 0.8.
        other => err_term(env, atoms::native_error(), other.to_string()),
    }
}

fn json_binary<'a>(env: Env<'a>, bytes: &[u8]) -> Term<'a> {
    let mut bin = NewBinary::new(env, bytes.len());
    bin.as_mut_slice().copy_from_slice(bytes);
    Term::from(bin)
}

fn ok_json<'a>(env: Env<'a>, value: &impl serde::Serialize) -> NifResult<Term<'a>> {
    let bytes = serde_json::to_vec(value).map_err(|e| {
        RustlerError::Term(Box::new((
            atoms::error(),
            atoms::invalid_report(),
            format!("serialize failed: {e}"),
        )))
    })?;
    Ok((atoms::ok(), json_binary(env, &bytes)).encode(env))
}

fn err_term<'a>(env: Env<'a>, reason: rustler::Atom, msg: impl Into<String>) -> Term<'a> {
    (atoms::error(), reason, msg.into()).encode(env)
}

#[rustler::nif(schedule = "DirtyCpu")]
fn extract_path<'a>(env: Env<'a>, path: String, options_json: String) -> NifResult<Term<'a>> {
    let opts = match parse_options(&options_json) {
        Ok(o) => o,
        Err(e) => return Ok(err_term(env, atoms::invalid_option(), e)),
    };
    let engine = match build_engine(&opts) {
        Ok(e) => e,
        Err(e) => return Ok(err_term(env, atoms::invalid_option(), e)),
    };
    match engine.extract_path(Path::new(&path)) {
        Ok(report) => ok_json(env, &report),
        Err(e) => Ok(map_io_error(env, e)),
    }
}

#[rustler::nif(schedule = "DirtyCpu")]
fn extract_bytes<'a>(
    env: Env<'a>,
    data: Binary<'a>,
    name: Option<String>,
    options_json: String,
) -> NifResult<Term<'a>> {
    let opts = match parse_options(&options_json) {
        Ok(o) => o,
        Err(e) => return Ok(err_term(env, atoms::invalid_option(), e)),
    };
    let engine = match build_engine(&opts) {
        Ok(e) => e,
        Err(e) => return Ok(err_term(env, atoms::invalid_option(), e)),
    };
    let bytes: Arc<[u8]> = Arc::from(data.as_slice().to_vec());
    let report = engine.extract_bytes(name.as_deref(), bytes);
    ok_json(env, &report)
}

#[rustler::nif(schedule = "DirtyCpu")]
fn llm_path<'a>(env: Env<'a>, path: String, options_json: String) -> NifResult<Term<'a>> {
    let opts = match parse_options(&options_json) {
        Ok(o) => o,
        Err(e) => return Ok(err_term(env, atoms::invalid_option(), e)),
    };
    let tokens = opts.tokens.unwrap_or(800);
    if tokens == 0 || tokens > MAX_TOKENS {
        return Ok(err_term(
            env,
            atoms::invalid_option(),
            format!("tokens must be 1..{MAX_TOKENS}"),
        ));
    }
    let engine = match build_engine(&opts) {
        Ok(e) => e,
        Err(e) => return Ok(err_term(env, atoms::invalid_option(), e)),
    };
    match engine.extract_path(Path::new(&path)) {
        Ok(report) => {
            let view = report.llm_view(tokens);
            ok_json(env, &view)
        }
        Err(e) => Ok(map_io_error(env, e)),
    }
}

#[rustler::nif(schedule = "DirtyCpu")]
fn llm_bytes<'a>(
    env: Env<'a>,
    data: Binary<'a>,
    name: Option<String>,
    options_json: String,
) -> NifResult<Term<'a>> {
    let opts = match parse_options(&options_json) {
        Ok(o) => o,
        Err(e) => return Ok(err_term(env, atoms::invalid_option(), e)),
    };
    let tokens = opts.tokens.unwrap_or(800);
    if tokens == 0 || tokens > MAX_TOKENS {
        return Ok(err_term(
            env,
            atoms::invalid_option(),
            format!("tokens must be 1..{MAX_TOKENS}"),
        ));
    }
    let engine = match build_engine(&opts) {
        Ok(e) => e,
        Err(e) => return Ok(err_term(env, atoms::invalid_option(), e)),
    };
    let bytes: Arc<[u8]> = Arc::from(data.as_slice().to_vec());
    let report = engine.extract_bytes(name.as_deref(), bytes);
    ok_json(env, &report.llm_view(tokens))
}

#[rustler::nif]
fn native_version<'a>(env: Env<'a>) -> Term<'a> {
    let mut map = Map::new();
    map.insert(
        "whiff".into(),
        Value::String(env!("CARGO_PKG_VERSION").into()),
    );
    map.insert("crate".into(), Value::String("0.8.0".into()));
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
    // Always succeeds for this static payload.
    match serde_json::to_vec(&Value::Object(map)) {
        Ok(bytes) => (atoms::ok(), json_binary(env, &bytes)).encode(env),
        Err(e) => err_term(env, atoms::native_error(), e.to_string()),
    }
}

rustler::init!("Elixir.Whiff.Native");
