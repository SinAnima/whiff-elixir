# whiff

whiff identifies a file or a binary and returns a `whiff/1` report as a map
with string keys: format, hashes, security and rights signals, content, and
format-specific metadata.

It wraps the Rust [whiff](https://github.com/baoulo/whiff) crate (0.8.0)
through a Rustler NIF. Elixir extractors and analyzers can add fields to the
native report; they run in isolated BEAM processes after native extraction.

## Report shape

Abbreviated:

```elixir
%{
  "whiff" => %{"schema" => "whiff/1", "version" => "0.8.0", "profile" => "standard"},
  "source" => %{"path" => "invoice.pdf", "name" => "invoice.pdf", "extension" => "pdf"},
  "identification" => %{"format" => "pdf", "mime" => "application/pdf", "extractor" => "doc.pdf"},
  "integrity" => %{"sha256" => "...", "blake3" => "..."},
  "security" => %{"risks" => [...], "secrets" => %{...}, "personal_data" => %{...}},
  "content" => %{"title" => "...", "excerpt" => "...", "keywords" => [...]},
  "metadata" => %{...},
  "format" => %{...},
  "embedded" => [...],
  "diagnostics" => %{"extractors" => [...], "warnings" => [...], "truncated" => false}
}
```

Empty optional fields are omitted. The schema is vendored at
`priv/schemas/whiff-1.schema.json`.

## Supported formats

Format coverage comes from upstream whiff. See
[metadata extracted per file format](https://github.com/baoulo/whiff/blob/main/docs/metadata-extracted.md).
This package builds the NIF with the `common` feature set only. The upstream
`geo`, `science`, `data`, `cad`, `forensics`, `games`, and `full` features are
not enabled. Other formats can be handled with an Elixir `Whiff.Extractor`.

## Install

```elixir
def deps do
  [{:whiff, "~> 0.4.0"}]
end
```

Precompiled NIFs are downloaded from GitHub Releases for the targets listed
under [Platform support](#platform-support). To build from source instead,
set `WHIFF_BUILD=1` and install Rust 1.91 or later. Source builds are the
default in `:dev` and `:test`.

## Configuration

All keys are optional. The values shown are the defaults.

```elixir
config :whiff,
  # Plugins used when a call does not pass :extractors / :analyzers.
  # A per-call list replaces these lists.
  extractors: [],
  analyzers: [],
  # Concurrent native calls (1..128).
  native_max_concurrency: 8,
  # How long a call waits for a native slot before returning
  # {:error, %Whiff.Error{reason: :overloaded}} (ms).
  native_wait_ms: 60_000,
  # Scratch directory for stage: :local (default: System.tmp_dir!()/whiff-scratch).
  scratch_dir: nil,
  # Largest file stage: :local will copy (bytes).
  scratch_max_bytes: 1_073_741_824
```

## Usage

### Extract a file

```elixir
{:ok, report} = Whiff.extract("invoice.pdf")
report["identification"]["format"]
#=> "pdf"
```

`extract/2` returns `{:ok, report}` for any file it can inspect, including
corrupt or unreadable ones. Problems inside the file are listed in
`report["diagnostics"]`. It returns `{:error, %Whiff.Error{}}` when the path
cannot be inspected or an option is invalid:

```elixir
case Whiff.extract(path) do
  {:ok, report} -> {:ok, report}
  {:error, %Whiff.Error{reason: :enoent}} -> :missing
  {:error, %Whiff.Error{reason: :eacces}} -> :denied
  {:error, %Whiff.Error{reason: :invalid_option, message: message}} -> {:bad_options, message}
  {:error, %Whiff.Error{} = err} -> {:error, err}
end
```

Bang variants (`extract!/2`, `extract_binary!/2`, `llm!/2`) raise the same
`%Whiff.Error{}`.

### Extract bytes

```elixir
{:ok, report} = Whiff.extract_binary(bytes, name: "invoice.pdf", hashes: [:sha256])
```

`:name` drives extension-based detection and `source.name`. Without it,
detection uses content only.

### Uploads

`Plug.Upload` temporary files have no extension, so pass the client file
name. For small uploads:

```elixir
def inspect_upload(%Plug.Upload{path: path, filename: filename}) do
  with {:ok, bytes} <- File.read(path),
       {:ok, report} <- Whiff.extract_binary(bytes, name: filename) do
    {:ok, report["identification"]["format"], get_in(report, ["integrity", "sha256"])}
  end
end
```

### LLM context

```elixir
{:ok, view} = Whiff.llm("contract.pdf", tokens: 800)
```

`llm/2` returns upstream's `Report::llm_view` projection. Elixir extractors
and analyzers do not run for it.

### Batches

```elixir
{:ok, results} =
  Whiff.extract_many(Path.wildcard("inbox/**/*"),
    max_concurrency: 4,
    timeout: 120_000,
    profile: :minimal,
    hashes: :none
  )

for {path, {:ok, report}} <- results, do: {path, report["identification"]["format"]}
```

Each path runs in its own unlinked task. Results keep input order. With
`on_error: :halt` the first error is returned, with the completed pairs in
`err.details.partial`.

### Slow or network filesystems

Path extraction reads the file inside a DirtyCpu NIF. On NFS or similar
mounts a slow read holds a DirtyCpu thread. `stage: :local` copies the file
to `:scratch_dir` on the BEAM first:

```elixir
{:ok, report} = Whiff.extract("/mnt/nfs/ingest/archive.zip", stage: :local)
```

The copy is made in a private (0700) directory with a random name and is
deleted after the call. The report still describes the original file:
`source.path` and filesystem fields are rewritten from the original. Times
are at second precision, and fields Elixir cannot read (birth time, ACLs,
xattrs, owner names, allocated size) are omitted; a `diagnostics.warnings`
entry says so. Files over `:scratch_max_bytes` return `:invalid_option`.

## Options

Each function rejects options it does not use.

| Option | Values | Default | Functions |
|---|---|---|---|
| `profile:` | `:minimal`, `:standard`, `:full`, `:llm` | `:standard` | all |
| `hashes:` | `:all`, `:none`, or a list of `:sha256` / `:blake3` | `:all` | all |
| `privacy:` | `:strict`, `:off` | `:strict` | all |
| `only:` / `skip:` | extractor ids or groups, for example `["text.keywords"]` | none | all |
| `format:` | format id to force, for example `"pdf"` | detect | all |
| `provenance:` | record which extractor set each field | `false` | all |
| `limits:` | see `Whiff` module docs for keys and ranges | profile limits | all |
| `stage:` | `:never`, `:local` | `:never` | `extract`, `llm`, `extract_many` |
| `name:` / `filename:` / `mime:` | strings | none | `extract_binary` |
| `tokens:` | 1..100_000 | `800` | `llm` |
| `mode:` | `:fallback`, `:augment`, `:override` | `:fallback` | `extract`, `extract_binary`, `extract_many` |
| `extractors:` / `analyzers:` | behaviour modules | app config | same |
| `strict:` | plugin failure returns `{:error, _}` | `false` | same |
| `plugin_timeout_ms:` | 1..600_000 | `5000` | same |
| `override_fields:` | dotted paths, for example `["content.title"]` | `[]` | same |
| `max_concurrency:` / `on_error:` / `timeout:` | see `Whiff.extract_many/2` | `4` / `:collect` / `300_000` | `extract_many` |

Privacy: `:strict` reduces personal data in structured fields to counts and
scrubs Elixir plugin patches with `Whiff.Privacy`. Upstream redacts secrets
and the text excerpt in both modes. `:off` lists personal data as found and
passes plugin patches through unchanged.

## Elixir extractors and analyzers

An extractor implements `Whiff.Extractor`; an analyzer implements
`Whiff.Analyzer`. Both return a patch that `Whiff.Merge` merges into the
report.

| Mode | When an extractor runs | Existing native values |
|---|---|---|
| `:fallback` | only if native extraction did not cover the file and could read it | kept, except `content.*` |
| `:augment` | whenever `supports?/2` returns `true` | kept |
| `:override` | whenever `supports?/2` returns `true` | replaced for paths in `override_fields` |

Merge rules that hold in every mode:

- `whiff`, `integrity`, and `embedded` cannot be patched.
- `diagnostics` accepts only `warnings`. Plugin runs are recorded by the
  pipeline in `diagnostics.extractors`.
- `security.risks` entries are appended with `source: "elixir:<id>"`; other
  existing `security` values are never replaced.
- `metadata` and `format` keys are namespaces (`"myapp.trade"`); an existing
  namespace is a conflict unless declared in `override_fields`.
- A value written by one plugin cannot be replaced by another plugin unless
  declared.
- Patches are limited in depth, size, and value types.

A failed plugin (raise, exit, timeout, invalid patch, conflict) is recorded in
`diagnostics.extractors` with `"status" => "error"`, and the call still
returns `{:ok, report}`. With `strict: true` the call returns the error.

```elixir
{:ok, report} =
  Whiff.extract("positions/2026-10-28.trade",
    extractors: [MyApp.TradeWhiffer],
    analyzers: [MyApp.SensitivityAnalyzer]
  )

report["format"]["myapp.trade"]
```

See the `Whiff.Extractor` and `Whiff.Analyzer` docs for complete modules, and
[`examples/trade_whiffer`](examples/trade_whiffer/README.md) for a separate
package that registers an extractor.

## Concurrency and limits

- Native calls are bounded by `:native_max_concurrency`. A call that waits
  longer than `:native_wait_ms` returns `:overloaded`. A process that exits
  while holding a slot releases it.
- Native `limits` apply to the Rust engine only. Plugin callbacks use
  `plugin_timeout_ms`.
- A native `file_timeout` can leave a worker thread running after the call
  returns. BEAM timeouts cannot stop native work.

## Requirements

| Component | Version |
|---|---|
| Elixir | 1.18 or later |
| OTP | 26 or later (CI tests 26 and 27) |
| Rust, for source builds | 1.91 or later |
| Rustler (Hex) | `~> 0.38` |

### Platform support

| Target | Status |
|---|---|
| `x86_64-unknown-linux-gnu`, `aarch64-apple-darwin` | tested in CI |
| `aarch64-unknown-linux-gnu`, `x86_64-apple-darwin` | precompiled, not tested in CI |
| `x86_64-pc-windows-msvc` | precompiled, tested in CI as best effort |
| musl | not supported |

## Limitations

- `extract_binary/2` copies the binary once into native memory.
- Elixir callbacks never run inside native extraction or for embedded children.
- There is no streaming NIF; inputs are a path or a binary.
- `stage: :local` copies the whole file before extraction.
- `Whiff.Error` messages for IO errors include the full path. Log
  `Path.basename(err.path)` if paths are sensitive.

## Development

```bash
mix deps.get
mix test
mix ci        # compile, format, credo, doctor, coveralls, docs
(cd native/whiff_native && cargo test && cargo clippy --all-targets -- -D warnings)
```

Golden reports in `test/fixtures/golden/` come from the Rust probe:

```bash
cargo build --release --manifest-path probes/rust_extract/Cargo.toml
probes/rust_extract/target/release/whiff_rust_extract_probe --golden test/fixtures/hello.txt \
  > test/fixtures/golden/hello.txt.json
```

Design record: [`docs/adr/0001-baseline.md`](docs/adr/0001-baseline.md).
Release steps: [`docs/hex-publish-checklist.md`](docs/hex-publish-checklist.md).

## License

MIT. Upstream whiff is also MIT.
