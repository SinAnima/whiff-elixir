//! Exposes the resolved upstream `whiff` crate version as `WHIFF_CRATE_VERSION`
//! so `native_version/0` cannot drift from `Cargo.lock`.

use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap_or_default());
    let lock_path = manifest_dir.join("Cargo.lock");
    println!("cargo:rerun-if-changed={}", lock_path.display());

    let version = fs::read_to_string(&lock_path)
        .ok()
        .and_then(|lock| whiff_version(&lock))
        .unwrap_or_else(|| "unknown".to_string());

    println!("cargo:rustc-env=WHIFF_CRATE_VERSION={version}");
}

fn whiff_version(lock: &str) -> Option<String> {
    let mut in_whiff = false;
    for line in lock.lines() {
        let line = line.trim();
        if line == "[[package]]" {
            in_whiff = false;
        } else if line == "name = \"whiff\"" {
            in_whiff = true;
        } else if in_whiff && let Some(rest) = line.strip_prefix("version = \"") {
            return rest.strip_suffix('"').map(str::to_string);
        }
    }
    None
}
