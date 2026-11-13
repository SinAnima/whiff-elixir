# whiff_native

Rustler NIF crate for the Elixir `whiff` package (0.4.0). It wraps the
[whiff](https://crates.io/crates/whiff) crate 0.8.0 with
`default-features = false, features = ["common"]`.

- Extraction NIFs run on the DirtyCpu scheduler.
- Options arrive as JSON; reports leave as UTF-8 JSON bytes.
- Every NIF returns `{:ok, binary}` or `{:error, reason, message}`. Panics are
  caught and returned as `:native_error`.
- Paths are passed as raw bytes (any bytes on Unix, UTF-8 on Windows).
- `build.rs` reads the resolved `whiff` version from `Cargo.lock` for
  `native_version/0`.

```bash
cargo test
cargo clippy --all-targets -- -D warnings
```
