//! Stage 0 probe: pin whiff 0.8.0 and exercise Engine / llm_view / errors.

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

use whiff::{Engine, Error, Hashes, Privacy, Profile};

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/hello.txt")
}

/// `--golden <file>`: print the report with the Elixir wrapper's default
/// options (standard profile, default hashes, strict privacy) as compact JSON.
/// Used to regenerate `test/fixtures/golden/*.json`.
fn golden(path: &str) -> ExitCode {
    let engine = Engine::builder().build();
    match engine.extract_path(path) {
        Ok(report) => match serde_json::to_string(&report) {
            Ok(json) => {
                println!("{json}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("serialize failed: {e}");
                ExitCode::FAILURE
            }
        },
        Err(err) => {
            eprintln!("extract_path failed: {err}");
            ExitCode::FAILURE
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    if args.get(1).map(String::as_str) == Some("--golden") {
        return match args.get(2) {
            Some(path) => golden(path),
            None => {
                eprintln!("usage: rust_extract --golden <file>");
                ExitCode::FAILURE
            }
        };
    }

    let path = args.get(1).map(PathBuf::from).unwrap_or_else(fixture_path);

    println!("whiff schema={}", whiff::SCHEMA);
    println!("enabled features={:?}", whiff::enabled_features());
    println!("extracting {}", path.display());

    let mut hashes = Hashes::NONE;
    hashes.sha256 = true;

    let engine = Engine::builder()
        .profile(Profile::Standard)
        .hashes(hashes)
        .privacy(Privacy::Strict)
        .provenance(false)
        .build();

    match engine.extract_path(&path) {
        Ok(report) => {
            let json = match serde_json::to_string_pretty(&report) {
                Ok(j) => j,
                Err(e) => {
                    eprintln!("serialize failed: {e}");
                    return ExitCode::FAILURE;
                }
            };
            println!("--- report ---");
            println!("{json}");

            let compact = report.llm_view(800);
            println!("--- llm_view(800) ---");
            println!(
                "{}",
                serde_json::to_string_pretty(&compact).unwrap_or_default()
            );

            let missing = path.with_file_name("definitely-missing-whiff-probe.bin");
            match engine.extract_path(&missing) {
                Err(Error::Io { path: p, source }) => {
                    println!("--- missing path ---");
                    println!(
                        "path={} kind={:?} message={source}",
                        p.display(),
                        source.kind()
                    );
                }
                Err(other) => println!("unexpected error for missing path: {other}"),
                Ok(_) => println!("unexpected ok for missing path"),
            }

            let bytes = b"probe bytes\n".as_slice();
            let mem = Engine::builder()
                .profile(Profile::Minimal)
                .hashes(Hashes::NONE)
                .build()
                .extract_bytes(Some("probe.txt"), bytes);
            println!("--- extract_bytes ---");
            println!(
                "format={:?} truncated={}",
                mem.identification.format, mem.diagnostics.truncated
            );

            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("extract_path failed: {err}");
            ExitCode::FAILURE
        }
    }
}
