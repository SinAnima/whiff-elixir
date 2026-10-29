# whiff_native

Rustler NIF crate wrapping [whiff](https://crates.io/crates/whiff) 0.5.1
(`default-features = false`, `features = ["common"]`).

NIFs run on the **DirtyCpu** scheduler. Options arrive as JSON; reports leave as UTF-8 JSON bytes.
