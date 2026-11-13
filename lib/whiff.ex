defmodule Whiff do
  @moduledoc """
  Elixir wrapper around the Rust [whiff](https://github.com/baoulo/whiff) crate.

  `extract/2` and `extract_binary/2` return a `whiff/1` report: a map with
  string keys describing what a file is (identification), its hashes
  (integrity), security and rights signals, content, and format metadata.

  Non-bang functions return `{:ok, value}` or `{:error, %Whiff.Error{}}` and do
  not raise. Bang functions return the value or raise the same
  `%Whiff.Error{}`.

  Native identification and extraction run in a NIF on the DirtyCpu
  scheduler. Elixir extractors (`Whiff.Extractor`) and analyzers
  (`Whiff.Analyzer`) run afterwards in isolated BEAM processes, and their
  patches are merged by `Whiff.Merge`.

  ## Options

  Each function lists the options it accepts. An option a function does not
  use is rejected with `:invalid_option`.

  Native options (all extract and LLM functions):

  | Option | Values | Default |
  |---|---|---|
  | `:profile` | `:minimal`, `:standard`, `:full`, `:llm` | `:standard` |
  | `:hashes` | `:all`, `:none`, or a non-empty list of `:sha256` / `:blake3` | upstream default (`:all`) |
  | `:privacy` | `:strict`, `:off`. `:off` reports personal data unredacted and disables the Elixir patch scrub | `:strict` |
  | `:only` | extractor ids or groups to run exclusively, for example `["text.plain"]` | all |
  | `:skip` | extractor ids or groups never to run, for example `["text.keywords"]` | none |
  | `:format` | force a format id instead of detecting, for example `"pdf"` | detect |
  | `:provenance` | record which extractor set each field in `diagnostics.provenance` | `false` |
  | `:limits` | keyword list, see below | profile limits |

  `:limits` keys (native engine only; Elixir plugins use `:plugin_timeout_ms`):

  | Key | Range |
  |---|---|
  | `:max_read_bytes`, `:max_decompressed_bytes` | 1..4 GiB |
  | `:hash_max_bytes` | 0..4 GiB (0 = never hash) |
  | `:max_parse_bytes` | 0..256 MiB |
  | `:max_text_bytes` | 0..64 MiB |
  | `:max_depth` | 0..8 (0 = no recursion into children) |
  | `:max_children` | 0..500 |
  | `:file_timeout_ms`, `:extractor_timeout_ms` | 1..600_000 |

  Plugin options (`extract/2`, `extract_binary/2`, `extract_many/2`):

  | Option | Values | Default |
  |---|---|---|
  | `:mode` | `:fallback`, `:augment`, `:override` | `:fallback` |
  | `:extractors` | modules implementing `Whiff.Extractor`; replaces `config :whiff, extractors:` | app config |
  | `:analyzers` | modules implementing `Whiff.Analyzer`; replaces `config :whiff, analyzers:` | app config |
  | `:strict` | `true` turns the first plugin failure into `{:error, _}` | `false` |
  | `:plugin_timeout_ms` | 1..600_000 per callback | `5000` |
  | `:override_fields` | dotted paths `:override` may replace, for example `["content.title"]` | `[]` |

  Modes:

  * `:fallback` runs an extractor only when native extraction did not cover
    the file (see `Whiff.Report.native_covered?/1`). Native IO errors such as
    `:eacces` are returned and never trigger a fallback.
  * `:augment` runs supporting extractors after native extraction and adds
    fields without replacing native values.
  * `:override` runs supporting extractors and replaces the paths listed in
    `:override_fields`. `whiff`, `integrity`, `embedded`, and existing
    `security` values are never replaced.

  ## Quick start

      iex> {:ok, report} = Whiff.extract("test/fixtures/hello.txt", hashes: :none)
      iex> {report["whiff"]["schema"], report["identification"]["format"]}
      {"whiff/1", "text"}
  """

  alias Whiff.{Error, Input, Limiter, Native, Options, Registry, Report, Scratch}

  @version Mix.Project.config()[:version]
  @default_batch_timeout 300_000

  @typedoc """
  A decoded `whiff/1` report. Keys are strings at every level.

  ## Example

      %{
        "whiff" => %{"schema" => "whiff/1", "version" => "0.8.0", "profile" => "standard"},
        "identification" => %{"format" => "text", "mime" => "text/plain", "extractor" => "text.plain"},
        "diagnostics" => %{"extractors" => [%{"id" => "text.plain", "status" => "ok"}], "truncated" => false}
      }
  """
  @type report :: %{optional(String.t()) => term()}

  @typedoc """
  Result of a non-bang extract or LLM call.

  ## Examples

      {:ok, %{"whiff" => %{"schema" => "whiff/1"}}}
      {:error, %Whiff.Error{reason: :enoent, message: "...", path: "missing.pdf", details: %{}}}
  """
  @type result :: {:ok, report()} | {:error, Error.t()}

  @doc """
  Version of this package.

  ## Examples

      iex> Whiff.version() =~ ~r/^\\d+\\.\\d+\\.\\d+/
      true
  """
  @spec version() :: String.t()
  def version, do: @version

  @doc """
  Report schema identifier written to `report["whiff"]["schema"]`.

  ## Examples

      iex> Whiff.schema_version()
      "whiff/1"
  """
  @spec schema_version() :: String.t()
  def schema_version, do: Report.schema_version()

  @doc """
  Extract a `whiff/1` report from a file path.

  ## Arguments

  * `path` — file path as a binary. Any bytes are accepted on Unix; Windows
    paths must be valid UTF-8.
  * `opts` — native options, plugin options (see the moduledoc), and:
    * `:stage` — `:never` (default) or `:local`. `:local` copies the file into
      a private directory under `config :whiff, :scratch_dir` before the NIF
      opens it, which keeps slow network reads off DirtyCpu threads. The
      report still describes the original file: `source.path` and
      filesystem fields are rewritten from the original (times at second
      precision), and a `diagnostics.warnings` entry says which fields were
      omitted.

  ## Returns

  * `{:ok, report}`. Extractor problems inside a readable file are reported
    in `report["diagnostics"]`, not as errors.
  * `{:error, %Whiff.Error{}}` with reason:
    * `:enoent`, `:eacces` — the path cannot be inspected
    * `:invalid_option` — unknown or invalid option, or `stage: :local` over
      `:scratch_max_bytes`
    * `:unsupported_input` — `path` is not a binary, is empty, or contains NUL
    * `:native_error` — other IO failure or a caught native panic
    * `:overloaded` — no native slot within `config :whiff, :native_wait_ms`
    * `:extractor_error`, `:analyzer_error`, `:timeout`, `:conflict`,
      `:invalid_report` — plugin failure, only with `strict: true`

  ## Examples

      iex> {:ok, report} = Whiff.extract("test/fixtures/hello.txt", hashes: :none)
      iex> report["source"]["name"]
      "hello.txt"

      iex> {:error, err} = Whiff.extract("test/fixtures/missing.txt")
      iex> {err.reason, err.path}
      {:enoent, "test/fixtures/missing.txt"}

      iex> {:error, err} = Whiff.extract("test/fixtures/hello.txt", profile: :turbo)
      iex> {err.reason, err.message}
      {:invalid_option, "profile must be one of [:minimal, :standard, :full, :llm], got: :turbo"}

      iex> {:error, err} = Whiff.extract("test/fixtures/hello.txt", tokens: 10)
      iex> err.message
      "unknown option(s): [:tokens]"

      iex> Whiff.extract(123)
      {:error, %Whiff.Error{reason: :unsupported_input, message: "path must be a binary", path: nil, details: %{}}}
  """
  @spec extract(Path.t(), keyword()) :: result()
  def extract(path, opts \\ [])

  def extract(path, opts) when is_binary(path) do
    with {:ok, options} <- Options.validate(opts, :extract), do: do_extract(path, options)
  end

  def extract(_path, _opts), do: {:error, Error.new(:unsupported_input, "path must be a binary")}

  @doc """
  Same as `extract/2`, but returns the report or raises `%Whiff.Error{}`.

  ## Examples

      iex> Whiff.extract!("test/fixtures/hello.txt", hashes: :none)["whiff"]["schema"]
      "whiff/1"

      iex> try do
      ...>   Whiff.extract!("test/fixtures/missing.txt")
      ...> rescue
      ...>   e in Whiff.Error -> {e.reason, e.path}
      ...> end
      {:enoent, "test/fixtures/missing.txt"}
  """
  @spec extract!(Path.t(), keyword()) :: report()
  def extract!(path, opts \\ []), do: unwrap!(extract(path, opts))

  @doc """
  Extract a `whiff/1` report from bytes in memory.

  ## Arguments

  * `bytes` — the payload
  * `opts` — native options, plugin options (see the moduledoc), and:
    * `:name` or `:filename` (not both) — file name used for detection and
      `source.name`, for example `"invoice.pdf"`. Default: none (detection
      by content only; `Whiff.Input` uses `"input.bin"`).
    * `:mime` — MIME hint passed to plugins in `Whiff.Input`

  ## Returns

  * `{:ok, report}`
  * `{:error, %Whiff.Error{}}` — `:unsupported_input` when `bytes` is not a
    binary, `:invalid_option`, `:overloaded`, `:native_error`, or a plugin
    failure with `strict: true`

  ## Examples

      iex> bytes = File.read!("test/fixtures/hello.txt")
      iex> {:ok, report} = Whiff.extract_binary(bytes, name: "hello.txt", hashes: :none)
      iex> report["source"]["name"]
      "hello.txt"

      iex> {:error, err} = Whiff.extract_binary("x", name: "a.txt", filename: "b.txt")
      iex> err.message
      "pass either :name or :filename, not both"

      iex> Whiff.extract_binary(123)
      {:error, %Whiff.Error{reason: :unsupported_input, message: "expected a binary", path: nil, details: %{}}}
  """
  @spec extract_binary(binary(), keyword()) :: result()
  def extract_binary(bytes, opts \\ [])

  def extract_binary(bytes, opts) when is_binary(bytes) do
    with {:ok, options} <- Options.validate(opts, :extract_binary),
         %Input{} = input <- Input.from_binary(bytes, opts),
         {:ok, report} <- native_bytes(bytes, Map.get(options, :name, options[:filename]), options) do
      Registry.run(input, report, options)
    end
  end

  def extract_binary(_bytes, _opts),
    do: {:error, Error.new(:unsupported_input, "expected a binary")}

  @doc """
  Same as `extract_binary/2`, but returns the report or raises `%Whiff.Error{}`.

  ## Examples

      iex> Whiff.extract_binary!("hello\\n", name: "hello.txt", hashes: :none)["source"]["name"]
      "hello.txt"

      iex> Whiff.extract_binary!("x", nope: 1)
      ** (Whiff.Error) invalid_option: unknown option(s): [:nope]
  """
  @spec extract_binary!(binary(), keyword()) :: report()
  def extract_binary!(bytes, opts \\ []), do: unwrap!(extract_binary(bytes, opts))

  @doc """
  Compact projection of a file's report for LLM context (upstream
  `Report::llm_view`).

  Elixir extractors and analyzers do not run for this function.

  ## Arguments

  * `path` — file path as a binary
  * `opts` — native options (see the moduledoc), `:stage` (as in `extract/2`), and:
    * `:tokens` — approximate token budget, 1..100_000 (default `800`)

  ## Returns

  * `{:ok, projection}` — string-keyed map
  * `{:error, %Whiff.Error{}}` — same reasons as `extract/2`, without plugin errors

  ## Examples

      iex> {:ok, view} = Whiff.llm("test/fixtures/hello.txt", tokens: 200, hashes: :none)
      iex> is_map(view)
      true

      iex> {:error, err} = Whiff.llm("test/fixtures/hello.txt", extractors: [])
      iex> err.message
      "unknown option(s): [:extractors]"

      iex> Whiff.llm(123)
      {:error, %Whiff.Error{reason: :unsupported_input, message: "path must be a binary", path: nil, details: %{}}}
  """
  @spec llm(Path.t(), keyword()) :: result()
  def llm(path, opts \\ [])

  def llm(path, opts) when is_binary(path) do
    with {:ok, options} <- Options.validate(opts, :llm),
         {:ok, tag} <- Scratch.stage(path, options) do
      try do
        json = Options.to_native_json(options)

        case Limiter.with_native(fn -> call_native(:llm_path, [Scratch.path(path, tag), json]) end) do
          {:ok, view} -> {:ok, view}
          {:error, err} -> {:error, Scratch.restore_error(with_path(err, path), tag)}
        end
      after
        Scratch.cleanup(tag)
      end
    end
  end

  def llm(_path, _opts), do: {:error, Error.new(:unsupported_input, "path must be a binary")}

  @doc """
  Same as `llm/2`, but returns the projection or raises `%Whiff.Error{}`.

  ## Examples

      iex> is_map(Whiff.llm!("test/fixtures/hello.txt", tokens: 200, hashes: :none))
      true

      iex> Whiff.llm!("test/fixtures/hello.txt", tokens: 0)
      ** (Whiff.Error) invalid_option: tokens must be an integer in 1..100000, got: 0
  """
  @spec llm!(Path.t(), keyword()) :: report()
  def llm!(path, opts \\ []), do: unwrap!(llm(path, opts))

  @doc """
  Extract many paths with bounded concurrency.

  Each path runs in its own unlinked task, so a crash in one path cannot stop
  the caller or the others.

  ## Arguments

  * `paths` — list of path binaries. A non-binary element yields an
    `:unsupported_input` result for that element.
  * `opts` — the options of `extract/2`, plus:
    * `:max_concurrency` — 1..128 (default `4`). Native calls are also bounded
      by `config :whiff, :native_max_concurrency`.
    * `:on_error` — `:collect` (default) returns every result; `:halt` stops
      at the first error and returns it with `details.partial` holding the
      `{path, result}` pairs completed before it
    * `:timeout` — per-path limit in ms, 1..3_600_000, or `:infinity`
      (default `300_000`). A path that exceeds it is killed and yields
      `{:error, %Whiff.Error{reason: :timeout}}`. Killing the task does not
      stop native work already running in the NIF.

  ## Returns

  * `{:ok, [{path, result}]}` — one pair per input, in input order
  * `{:error, %Whiff.Error{}}` — invalid arguments or options, or the first
    error with `on_error: :halt`

  ## Examples

      iex> path = "test/fixtures/hello.txt"
      iex> {:ok, [{^path, {:ok, report}}]} = Whiff.extract_many([path], hashes: :none, max_concurrency: 1)
      iex> report["whiff"]["schema"]
      "whiff/1"

      iex> {:error, err} = Whiff.extract_many(["test/fixtures/hello.txt", "test/fixtures/missing.txt"], on_error: :halt, max_concurrency: 1)
      iex> {err.reason, length(err.details.partial)}
      {:enoent, 1}

      iex> Whiff.extract_many("nope")
      {:error, %Whiff.Error{reason: :unsupported_input, message: "paths must be a list", path: nil, details: %{}}}
  """
  @spec extract_many([Path.t()], keyword()) ::
          {:ok, [{Path.t(), result()}]} | {:error, Error.t()}
  def extract_many(paths, opts \\ [])

  def extract_many(paths, opts) when is_list(paths) do
    with {:ok, options} <- Options.validate(opts, :extract_many) do
      with_task_supervisor(&run_batch(&1, paths, options))
    end
  end

  def extract_many(_paths, _opts),
    do: {:error, Error.new(:unsupported_input, "paths must be a list")}

  defp run_batch(sup, paths, options) do
    timeout = Map.get(options, :timeout, @default_batch_timeout)

    sup
    |> Task.Supervisor.async_stream_nolink(
      paths,
      fn path -> {path, extract_validated(path, options)} end,
      max_concurrency: Map.get(options, :max_concurrency, 4),
      timeout: timeout,
      on_timeout: :kill_task,
      ordered: true,
      zip_input_on_exit: true
    )
    |> Stream.map(&batch_result(&1, timeout))
    |> reduce_many(Map.get(options, :on_error, :collect))
  end

  defp extract_validated(path, options) when is_binary(path), do: do_extract(path, options)

  defp extract_validated(_path, _options),
    do: {:error, Error.new(:unsupported_input, "path must be a binary")}

  defp batch_result({:ok, pair}, _timeout), do: pair

  defp batch_result({:exit, {path, :timeout}}, timeout),
    do:
      {path,
       {:error, Error.new(:timeout, "extraction exceeded #{timeout}ms", path: maybe_path(path))}}

  defp batch_result({:exit, {path, reason}}, _timeout) do
    kind = if is_tuple(reason), do: elem(reason, 0), else: reason

    {path,
     {:error,
      Error.new(:native_error, "extraction task exited: #{inspect(kind)}", path: maybe_path(path))}}
  end

  defp maybe_path(path) when is_binary(path), do: path
  defp maybe_path(_), do: nil

  defp reduce_many(stream, :collect), do: {:ok, Enum.to_list(stream)}

  defp reduce_many(stream, :halt) do
    Enum.reduce_while(stream, {:ok, []}, fn
      {path, {:error, %Error{} = err}}, {:ok, acc} ->
        partial = Enum.reverse(acc)

        {:halt,
         {:error,
          %{
            err
            | path: err.path || maybe_path(path),
              details: Map.put(err.details, :partial, partial)
          }}}

      pair, {:ok, acc} ->
        {:cont, {:ok, [pair | acc]}}
    end)
    |> case do
      {:ok, acc} -> {:ok, Enum.reverse(acc)}
      error -> error
    end
  end

  defp with_task_supervisor(fun) do
    case Process.whereis(Whiff.TaskSupervisor) do
      nil ->
        # :whiff not started: use a temporary supervisor for this call.
        {:ok, sup} = Task.Supervisor.start_link()

        try do
          fun.(sup)
        after
          Supervisor.stop(sup)
        end

      _pid ->
        fun.(Whiff.TaskSupervisor)
    end
  end

  defp do_extract(path, options) do
    with {:ok, tag} <- Scratch.stage(path, options) do
      try do
        json = Options.to_native_json(options)
        staged = Scratch.path(path, tag)

        case Limiter.with_native(fn -> call_native(:extract_path, [staged, json]) end) do
          {:ok, report} ->
            Registry.run(Input.from_path(path), Scratch.restore_report(report, tag), options)

          {:error, err} ->
            {:error, Scratch.restore_error(with_path(err, staged), tag)}
        end
      after
        Scratch.cleanup(tag)
      end
    end
  end

  defp native_bytes(bytes, name, options) do
    json = Options.to_native_json(options)

    case Limiter.with_native(fn -> call_native(:extract_bytes, [bytes, name, json]) end) do
      {:ok, report} -> {:ok, report}
      {:error, err} -> {:error, if(name, do: with_path(err, name), else: err)}
    end
  end

  # The NIF returns tagged tuples and catches panics. The rescue is a second
  # line of defense (for example a NIF that failed to load).
  defp call_native(fun, args) do
    case apply(Native, fun, args) do
      {:ok, json} ->
        Report.decode(json)

      {:error, reason, message} when is_atom(reason) and is_binary(message) ->
        {:error, Error.new(reason, message)}
    end
  rescue
    e in [ErlangError, ArgumentError, UndefinedFunctionError] ->
      {:error, Error.new(:native_error, "native call failed: #{inspect(e.__struct__)}")}
  end

  defp with_path(%Error{path: nil} = err, path), do: %{err | path: path}
  defp with_path(err, _path), do: err

  defp unwrap!({:ok, value}), do: value
  defp unwrap!({:error, %Error{} = err}), do: raise(err)
end
