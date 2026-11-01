# whiff

**whiff** is an Elixir library that sniffs a file (or in-memory bytes) and returns one structured **`whiff/1`** report: what the file is, how it was identified, hashes, rights/security signals, content excerpts, and format-specific metadata — as a **string-keyed** map you can pattern-match and pipe through the rest of your app.

It wraps the Rust [whiff](https://github.com/baoulo/whiff) crate (`0.6.0`) through a Rustler NIF, and adds first-class **Elixir extractors** (“Whiffers”) and **analyzers** that run in BEAM processes *outside* the native engine.

## What you get

A typical report looks like this (shape abbreviated):

```elixir
%{
  "whiff" => %{"schema" => "whiff/1", "version" => "0.6.0", "profile" => "standard"},
  "identification" => %{
    "format" => "pdf",
    "mime" => "application/pdf",
    "name" => "PDF document",
    "extractor" => "..."
  },
  "integrity" => %{"sha256" => "...", "blake3" => "..."},
  "security" => %{"risks" => [...], "secrets" => [...], "personal_data" => [...]},
  "content" => %{"title" => "...", "excerpt" => "...", "keywords" => [...]},
  "metadata" => %{...},   # EXIF / XMP / … when present
  "format" => %{...},     # format-specific technical details
  "embedded" => [...],    # children of archives/containers
  "diagnostics" => %{"extractors" => [...], "truncated" => false, ...}
}
```

Empty optional fields are omitted; core sections stay present. Schema: `whiff/1` (vendored at `priv/schemas/whiff-1.schema.json`).

Native extraction is the default. Elixir plugins can **fallback** for proprietary formats, **augment** a native report with domain fields, or **override** declared fields — with deterministic merge rules that refuse to silently wipe security/integrity/diagnostics.

## Supported file types

Format coverage comes from upstream Rust **whiff**. The authoritative list of formats, what each extractor pulls, and which Cargo feature enables it is here:

**[whiff: metadata extracted per file format](https://github.com/baoulo/whiff/blob/main/docs/metadata-extracted.md)**

This Elixir package ships the NIF with the **`common`** feature set (text, web, data, code, images, documents, email, audio/video, archives, packages, executables, certificates, SQLite, fonts, …). Specialist collections (`geo`, `science`, `data`, `cad`, `forensics`, `games`, or `full`) are documented upstream but are **not** enabled in v0.1 of this wrapper.

Anything outside native coverage can still be handled with an Elixir `Whiff.Extractor` (see examples below).

## Good use cases

| Use case | Why whiff fits |
|---|---|
| **Upload / ingest gates** | Identify MIME/format, refuse surprising types, record hashes before storage |
| **Security / compliance triage** | Surface risks, secrets, and personal-data signals early in a pipeline |
| **Document / media catalogs** | Title, keywords, EXIF/rights, container children without ad-hoc parsers per type |
| **LLM / RAG prep** | `Whiff.llm/2` returns a compact, token-budgeted projection of the same report |
| **Proprietary formats** | Ship a small Elixir Whiffer for `.trade` / bank blobs while keeping native coverage for PDF/JPEG/ZIP |
| **Phoenix / LiveView uploads** | `extract_binary/2` on Plug upload bytes with `name:` for detection |
| **Batch jobs** | `extract_many/2` with bounded concurrency over a list of paths |
| **Forensic-ish inventory** | Profile/limits knobs, nested archives, Unicode names — same report shape everywhere |

Whiff is a **library**, not a service: no database, no HTTP API of its own. Call it from workers, controllers, or Mix tasks.

## Install

```elixir
def deps do
  [
    {:whiff, "~> 0.2.0"}
  ]
end
```

### Native NIF

- **Dev / test:** source-builds by default (`force_build`, or set `WHIFF_BUILD=1`). Needs Rust **1.91+**.
- **Prod / Hex:** precompiled NIFs from GitHub Releases. Tagging `vX.Y.Z` runs [`.github/workflows/release.yml`](.github/workflows/release.yml) (build artifacts → checksum → Hex publish).

## Requirements

| Piece | Version |
|---|---|
| Elixir | `~> 1.18` |
| OTP | 26+ (CI uses 27) |
| Rust (source / force build) | **1.91+** |
| Hex [Rustler](https://hex.pm/packages/rustler) | **`~> 0.38`** |

Rustler **0.39** is on crates.io but **not on Hex** as of 2026-10-28; this package pins **`~> 0.38`**.

### Platform support

| Target | Status |
|---|---|
| `x86_64-unknown-linux-gnu`, `aarch64-apple-darwin` | Mandatory CI |
| `aarch64-unknown-linux-gnu`, `x86_64-apple-darwin` | Precompiled / best-effort |
| `x86_64-pc-windows-msvc` | Best-effort |
| musl / static Linux | Deferred (not v0.1) |

## Examples

### Identify an uploaded file and gate storage

```elixir
def accept_upload(%Plug.Upload{path: path, filename: name}) do
  case Whiff.extract(path, profile: :standard, privacy: :strict) do
    {:ok, report} ->
      format = report["identification"]["format"]
      mime = report["identification"]["mime"]
      sha = get_in(report, ["integrity", "sha256"])

      cond do
        format in ~w(pdf jpeg png) ->
          {:ok, %{format: format, mime: mime, sha256: sha, report: report}}

        true ->
          {:error, {:unsupported_format, format || mime || name}}
      end

    {:error, %Whiff.Error{reason: :enoent}} ->
      {:error, :missing}

    {:error, %Whiff.Error{} = err} ->
      {:error, err}
  end
end
```

### Work from bytes (S3 object, email attachment, Plug body)

```elixir
{:ok, report} =
  Whiff.extract_binary(file_bytes,
    name: "invoice.pdf",
    hashes: [:sha256],
    privacy: :strict
  )

report["identification"]["format"]
#=> "pdf"

report["content"]["title"]
get_in(report, ["security", "risks"])
```

### Compact context for an LLM / agent

```elixir
{:ok, compact} = Whiff.llm("contracts/acme-msa.pdf", tokens: 800, privacy: :strict)

# `compact` is a smaller map derived from the full report (upstream llm_view),
# suitable as tool/RAG context without dumping the entire JSON document.
Req.post!(llm_url, json: %{messages: [%{role: "user", content: Jason.encode!(compact)}]})
```

### Flag secrets / PII before indexing

```elixir
{:ok, report} = Whiff.extract(path, profile: :full, privacy: :strict)

secrets = get_in(report, ["security", "secrets"]) || []
pii = get_in(report, ["security", "personal_data"]) || []

if secrets != [] or pii != [] do
  Logger.warning("sensitive payload",
    path_basename: Path.basename(path),
    secret_count: length(List.wrap(secrets)),
    pii_count: length(List.wrap(pii))
  )
end
```

Prefer **not** logging full paths, excerpts, or raw plugin output when privacy matters.

### Proprietary format via an Elixir Whiffer (`:fallback`)

Native whiff may detect “something text-like” but has no extractor for your format. Register a Whiffer; `:fallback` runs it when native coverage is insufficient (and **not** on inspect failures like `:eacces`).

```elixir
defmodule MyBank.TradeWhiffer do
  @behaviour Whiff.Extractor

  def id, do: "mybank.trade"
  def version, do: 1

  def supports?(%Whiff.Input{extension: ".trade"}, _native), do: true
  def supports?(_, _), do: false

  def extract(%Whiff.Input{path: path}, _native) do
    with {:ok, body} <- File.read(path),
         {:ok, trade} <- MyBank.TradeParser.parse(body) do
      {:ok,
       %{
         "content" => %{"title" => "Trade #{trade.id}"},
         "format" => %{
           "mybank.trade" => %{
             "trade_id" => trade.id,
             "currency" => trade.currency,
             "notional" => trade.notional
           }
         }
       }}
    else
      {:error, reason} ->
        {:error,
         Whiff.Error.new(:extractor_error, "trade parse failed",
           details: %{cause: inspect(reason)}
         )}
    end
  end
end

{:ok, report} =
  Whiff.extract("positions/USD-2026-10-28.trade",
    extractors: [MyBank.TradeWhiffer],
    mode: :fallback
  )

get_in(report, ["format", "mybank.trade", "trade_id"])
```

See [`examples/trade_whiffer`](examples/trade_whiffer/README.md) for a standalone package that depends on `whiff` without hardcoding into core.

### Enrich a known PDF (`:augment`) + post-pass analyzer

```elixir
defmodule MyApp.ContractWhiffer do
  @behaviour Whiff.Extractor
  def id, do: "myapp.contract"
  def version, do: 1
  def supports?(%Whiff.Input{extension: ".pdf"}, _n), do: true
  def supports?(_, _), do: false

  def extract(_input, _native) do
    # Native identification already ran; add namespaced domain metadata only.
    {:ok,
     %{
       "format" => %{"myapp.contract" => %{"reviewed" => false}},
       "content" => %{"keywords" => ["contract"]}
     }}
  end
end

defmodule MyApp.SensitivityAnalyzer do
  @behaviour Whiff.Analyzer
  def id, do: "myapp.sensitivity"
  def version, do: 1

  def analyze(report, _input) do
    title = get_in(report, ["content", "title"]) || ""
    {:ok, %{"metadata" => %{"myapp.sensitivity" => %{"title_len" => String.length(title)}}}}
  end
end

{:ok, report} =
  Whiff.extract("contract.pdf",
    mode: :augment,
    extractors: [MyApp.ContractWhiffer],
    analyzers: [MyApp.SensitivityAnalyzer]
  )
```

### Batch a directory with bounded concurrency

```elixir
paths = Path.wildcard("inbox/**/*.{pdf,jpg,png,zip}")

{:ok, results} =
  Whiff.extract_many(paths,
    max_concurrency: 4,
    on_error: :collect,
    profile: :minimal,
    hashes: :none
  )

for {path, {:ok, report}} <- results do
  IO.puts("#{path} -> #{report["identification"]["format"]}")
end
```

### Errors are structured (same type for bang / non-bang)

```elixir
case Whiff.extract("missing.pdf") do
  {:error, %Whiff.Error{reason: :enoent}} -> :missing
  {:error, %Whiff.Error{reason: :eacces}} -> :denied
  {:error, %Whiff.Error{reason: :invalid_option} = err} -> {:bad_opts, err.message}
  {:ok, report} -> {:ok, report}
end

# Bang variants raise the same %Whiff.Error{}
try do
  Whiff.extract!("missing.pdf")
rescue
  e in Whiff.Error -> {:raised, e.reason}
end
```

## Options (common)

| Option | Meaning |
|---|---|
| `profile:` | `:minimal` \| `:standard` (default) \| `:full` \| `:llm` |
| `hashes:` | `:all` \| `:none` \| `[:sha256]` \| `[:blake3]` \| both |
| `privacy:` | `:strict` (default) \| `:off` — `:off` can surface more PII |
| `limits:` | keyword list; Elixir + NIF enforce conservative caps |
| `mode:` | `:fallback` (default) \| `:augment` \| `:override` |
| `extractors:` / `analyzers:` | behaviour modules |
| `strict:` | plugin failure → `{:error, _}` instead of diagnostics |
| `plugin_timeout_ms:` | default `5000` |
| `tokens:` | LLM budget for `Whiff.llm/2` (default `800`) |

Native `limits` apply to the Rust engine. Elixir plugin timeouts are separate (`plugin_timeout_ms`).

**Privacy caveat:** upstream privacy analysis does **not** automatically cover fields added later by Elixir plugins. With `privacy: :strict`, plugin patches get a local scrub — not claimed equivalent to native redaction.

## Limitations (v0.1)

- Native `file_timeout` may abandon worker threads; BEAM timeouts cannot kill them.
- No zero-copy guarantee for `extract_binary` (data may be copied into `Arc<[u8]>`).
- No Elixir callbacks inside native recursion; no streaming `extract_reader` NIF.
- Do not log secrets, full paths, or raw binary content by default.

## Develop

```bash
mix deps.get
WHIFF_BUILD=1 mix test
mix ci                               # compile, format, credo, doctor, test --cover, docs
cargo run --manifest-path probes/rust_extract/Cargo.toml
```

Design notes: [`docs/adr/0001-baseline.md`](docs/adr/0001-baseline.md). Hex release: [`docs/hex-publish-checklist.md`](docs/hex-publish-checklist.md).

## License

MIT. Upstream Rust `whiff` is also MIT.
