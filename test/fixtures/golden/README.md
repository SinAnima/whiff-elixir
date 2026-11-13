# Golden reports

Reports produced by the pinned Rust whiff crate with the wrapper's default
options, used by `test/whiff/fidelity_test.exs`.

Host-dependent fields (`source.path`, `temporal.filesystem`, inode/device and
other `system` values, and file mode/owner/ACL/xattr `security` values) are
removed before the file is saved, and the test ignores them on both sides.

Regenerate after an upstream bump:

```bash
cargo build --release --manifest-path probes/rust_extract/Cargo.toml
for f in hello.txt tiny.jpg tiny.pdf sample.zip nested.zip corrupt.pdf empty.bin café.txt secret.secret pii.txt; do
  probes/rust_extract/target/release/whiff_rust_extract_probe --golden "test/fixtures/$f" \
    | python3 test/fixtures/golden/strip.py > "test/fixtures/golden/$f.json"
done
```
