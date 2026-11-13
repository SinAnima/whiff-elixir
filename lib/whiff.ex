defmodule Whiff do
  @moduledoc """
  Elixir wrapper around the Rust [whiff](https://github.com/baoulo/whiff) crate.

  Non-bang functions return `{:ok, report}` or `{:error, %Whiff.Error{}}`.
  Reports are **string-keyed** maps conforming to schema `whiff/1`.
  Bang variants raise `%Whiff.Error{}`.

  Native identification and extraction run in the NIF. Elixir extractors
  (`Whiff.Extractor`) and analyzers (`Whiff.Analyzer`) run in BEAM processes
  and merge patches via `Whiff.Merge`.

  ## Quick start

      iex> Whiff.schema_version()
      "whiff/1"

      iex> {:ok, report} = Whiff.extract("test/fixtures/hello.txt", hashes: :none)
      iex> report["whiff"]["schema"]
      "whiff/1"
  """

  alias Whiff.{Error, Input, Limiter, Native, Options, Registry, Report, Scratch}

  @typedoc """
  A decoded `whiff/1` report: string keys only.

  ## Example

      %{"whiff" => %{"schema" => "whiff/1"}, "identification" => %{"format" => "text"}}
  """
  @type report :: %{optional(String.t()) => term()}

  @typedoc """
  Public result tuple for non-bang extract/LLM APIs.

  ## Example

      {:ok, %{"whiff" => %{"schema" => "whiff/1"}}}
  """
  @type result :: {:ok, report()} | {:error, Error.t()}

  @doc """
  Library version string from the application vsn.

  ## Returns

  A semver-like string such as `"0.4.0"`.

  ## Examples

      iex> Whiff.version() =~ ~r/^\\d+\\.\\d+\\.\\d+/
      true
  """
  @spec version() :: String.t()
  def version, do: project_version()

  @doc """
  Report schema version (`"whiff/1"`).

  ## Examples

      iex> Whiff.schema_version()
      "whiff/1"
  """
  @spec schema_version() :: String.t()
  def schema_version, do: Report.schema_version()

  @doc """
  Extract a `whiff/1` report from a filesystem path.

  ## Arguments

  * `path` — UTF-8 filesystem path
  * `opts` — optional keywords (see below)

  ## Options

  Native:

  * `:profile` — extraction profile atom (for example `:standard`, `:minimal`)
  * `:hashes` — hash selection (for example `:none`, `:all`)
  * `:privacy` — `:strict` (default) or `:off` (also used for Elixir patches)
  * `:only` / `:skip` — section filters
  * `:format` / `:provenance` / `:limits` — forwarded to the native engine
  * `:tokens` — LLM token budget (`llm/2` only)

  Pipeline:

  * `:mode` — `:fallback` | `:augment` | `:override` (merge strategy)
  * `:extractors` / `:analyzers` — module lists (override app config)
  * `:strict` — when `true`, plugin errors fail the call
  * `:plugin_timeout_ms` — per-plugin task timeout
  * `:override_fields` — paths allowed under `:override`

  Staging:

  * `:stage` — `:never` (default) or `:local`. When `:local`, the file is copied
    to the configured scratch directory before the DirtyCpu NIF opens it.

  ## Returns

  * `{:ok, report}` — string-keyed `whiff/1` map
  * `{:error, %Whiff.Error{}}` — see `t:Whiff.Error.reason/0` (`:enoent`,
    `:invalid_option`, `:native_error`, plugin errors when `strict: true`, etc.)

  Does not raise; use `extract!/2` for that.

  ## Examples

      iex> {:ok, report} = Whiff.extract("test/fixtures/hello.txt", hashes: :none)
      iex> is_binary(report["identification"]["format"])
      true

      iex> Whiff.extract(123)
      {:error, %Whiff.Error{reason: :unsupported_input, message: "path must be a binary", path: nil, details: %{}}}
  """
  @spec extract(Path.t(), keyword()) :: result()
  def extract(path, opts \\ [])

  def extract(path, opts) when is_binary(path) and is_list(opts) do
    with {:ok, options} <- Options.validate(opts),
         {:ok, stage_tag} <- Scratch.stage(path, options) do
      staged_path = Scratch.path(path, stage_tag)

      try do
        input = Input.from_path(path)

        with {:ok, report} <- native_extract_path(staged_path, options) do
          Registry.run(input, report, options)
        end
      after
        Scratch.cleanup(stage_tag)
      end
    end
  end

  def extract(_, _) do
    {:error, Error.new(:unsupported_input, "path must be a binary")}
  end

  @doc """
  Same as `extract/2`, but returns the report or raises `%Whiff.Error{}`.

  ## Arguments

  * `path` — UTF-8 filesystem path
  * `opts` — same as `extract/2`

  ## Returns

  A string-keyed report map.

  ## Raises

  `%Whiff.Error{}` when `extract/2` would return `{:error, err}`.

  ## Examples

      iex> report = Whiff.extract!("test/fixtures/hello.txt", hashes: :none)
      iex> report["whiff"]["schema"]
      "whiff/1"
  """
  @spec extract!(Path.t(), keyword()) :: report()
  def extract!(path, opts \\ []) do
    case extract(path, opts) do
      {:ok, report} -> report
      {:error, %Error{} = err} -> raise err
    end
  end

  @doc """
  Extract a `whiff/1` report from in-memory bytes.

  ## Arguments

  * `bytes` — binary payload
  * `opts` — same as `extract/2`, plus:
    * `:name` / `:filename` — basename for detection (recommended)
    * `:mime` — optional MIME hint for `Whiff.Input`

  ## Returns

  * `{:ok, report}` — string-keyed map
  * `{:error, %Whiff.Error{}}` — `:unsupported_input`, `:invalid_option`,
    native failures, or strict plugin failures

  ## Examples

      iex> bytes = File.read!("test/fixtures/hello.txt")
      iex> {:ok, report} = Whiff.extract_binary(bytes, name: "hello.txt", hashes: :none)
      iex> report["whiff"]["schema"]
      "whiff/1"

      iex> Whiff.extract_binary(123)
      {:error, %Whiff.Error{reason: :unsupported_input, message: "expected a binary", path: nil, details: %{}}}
  """
  @spec extract_binary(binary(), keyword()) :: result()
  def extract_binary(bytes, opts \\ [])

  def extract_binary(bytes, opts) when is_binary(bytes) and is_list(opts) do
    with {:ok, options} <- Options.validate(opts),
         input <- build_binary_input(bytes, opts),
         {:ok, input} <- ok_input(input),
         {:ok, report} <- native_extract_bytes(bytes, input.filename, options) do
      Registry.run(input, report, options)
    end
  end

  def extract_binary(_, _) do
    {:error, Error.new(:unsupported_input, "expected a binary")}
  end

  @doc """
  Same as `extract_binary/2`, but returns the report or raises `%Whiff.Error{}`.

  ## Arguments

  * `bytes` — binary payload
  * `opts` — same as `extract_binary/2`

  ## Raises

  `%Whiff.Error{}` on failure.

  ## Examples

      iex> bytes = File.read!("test/fixtures/hello.txt")
      iex> Whiff.extract_binary!(bytes, name: "hello.txt", hashes: :none)["whiff"]["schema"]
      "whiff/1"
  """
  @spec extract_binary!(binary(), keyword()) :: report()
  def extract_binary!(bytes, opts \\ []) do
    case extract_binary(bytes, opts) do
      {:ok, report} -> report
      {:error, %Error{} = err} -> raise err
    end
  end

  @doc """
  Compact LLM projection for a path (`Report::llm_view` in upstream).

  ## Arguments

  * `path` — UTF-8 filesystem path
  * `opts` — native/pipeline options; `:tokens` defaults to `800`. Accepts
    `stage: :local` like `extract/2`.

  ## Returns

  * `{:ok, compact}` — string-keyed projection map
  * `{:error, %Whiff.Error{}}` — path/option/native failures

  ## Examples

      iex> {:ok, compact} = Whiff.llm("test/fixtures/hello.txt", tokens: 200, hashes: :none)
      iex> is_map(compact)
      true

      iex> Whiff.llm(123)
      {:error, %Whiff.Error{reason: :unsupported_input, message: "path must be a binary", path: nil, details: %{}}}
  """
  @spec llm(Path.t(), keyword()) :: result()
  def llm(path, opts \\ [])

  def llm(path, opts) when is_binary(path) and is_list(opts) do
    with {:ok, options} <- Options.validate(opts),
         {:ok, stage_tag} <- Scratch.stage(path, options) do
      staged_path = Scratch.path(path, stage_tag)

      try do
        json = Options.to_native_json(options)
        Limiter.with_native(fn -> call_llm_path(staged_path, json) end)
      after
        Scratch.cleanup(stage_tag)
      end
    end
  end

  def llm(_, _), do: {:error, Error.new(:unsupported_input, "path must be a binary")}

  @doc """
  Same as `llm/2`, but returns the projection or raises `%Whiff.Error{}`.

  ## Examples

      iex> is_map(Whiff.llm!("test/fixtures/hello.txt", tokens: 200, hashes: :none))
      true
  """
  @spec llm!(Path.t(), keyword()) :: report()
  def llm!(path, opts \\ []) do
    case llm(path, opts) do
      {:ok, report} -> report
      {:error, %Error{} = err} -> raise err
    end
  end

  @doc """
  Extract many paths with bounded concurrency.

  ## Arguments

  * `paths` — list of UTF-8 path strings
  * `opts` — forwarded to `extract/2`, plus:
    * `:max_concurrency` — positive integer (default `4`)
    * `:on_error` — `:collect` (default) keeps going; `:halt` stops and returns
      the first error with `:partial` results in `err.details`

  ## Returns

  * `{:ok, [{path, result}, ...]}` — one pair per input path, in order
    (`result` is `t:result/0`)
  * `{:error, %Whiff.Error{}}` — invalid args, invalid options, or `:halt` stop

  ## Examples

      iex> path = "test/fixtures/hello.txt"
      iex> {:ok, pairs} = Whiff.extract_many([path], hashes: :none, max_concurrency: 1)
      iex> match?([{^path, {:ok, _}}], pairs)
      true

      iex> Whiff.extract_many("nope")
      {:error, %Whiff.Error{reason: :unsupported_input, message: "paths must be a list of binaries", path: nil, details: %{}}}
  """
  @spec extract_many([Path.t()], keyword()) ::
          {:ok, [{Path.t(), result()}]} | {:error, Error.t()}
  def extract_many(paths, opts \\ [])

  def extract_many(paths, opts) when is_list(paths) and is_list(opts) do
    with {:ok, options} <- Options.validate(opts) do
      max = Map.get(options, :max_concurrency, 4)
      on_error = Map.get(options, :on_error, :collect)
      extract_opts = Keyword.drop(opts, [:max_concurrency, :on_error])

      stream =
        Task.async_stream(
          paths,
          fn path -> {path, extract(path, extract_opts)} end,
          max_concurrency: max,
          timeout: :infinity,
          ordered: true
        )

      reduce_many(stream, on_error)
    end
  end

  def extract_many(_, _) do
    {:error, Error.new(:unsupported_input, "paths must be a list of binaries")}
  end

  defp reduce_many(stream, :collect) do
    results =
      Enum.map(stream, fn
        {:ok, pair} ->
          pair

        {:exit, reason} ->
          {"", {:error, Error.new(:native_error, "task exited: #{inspect(reason)}")}}
      end)

    {:ok, results}
  end

  defp reduce_many(stream, :halt) do
    Enum.reduce_while(stream, {:ok, []}, fn
      {:ok, {path, {:error, %Error{} = err}}}, {:ok, acc} ->
        {:halt,
         {:error,
          %{
            err
            | path: err.path || path,
              details: Map.put(err.details, :partial, Enum.reverse(acc))
          }}}

      {:ok, pair}, {:ok, acc} ->
        {:cont, {:ok, [pair | acc]}}

      {:exit, reason}, {:ok, _} ->
        {:halt, {:error, Error.new(:native_error, "task exited: #{inspect(reason)}")}}
    end)
    |> case do
      {:ok, acc} -> {:ok, Enum.reverse(acc)}
      {:error, _} = err -> err
    end
  end

  defp native_extract_path(path, options) do
    json = Options.to_native_json(options)
    Limiter.with_native(fn -> call_extract_path(path, json) end)
  end

  defp native_extract_bytes(bytes, name, options) do
    json = Options.to_native_json(options)
    Limiter.with_native(fn -> call_extract_bytes(bytes, name, json) end)
  end

  defp call_llm_path(path, json) do
    case Native.llm_path(path, json) do
      {:ok, bin} -> Report.decode(bin)
      {:error, reason, message} -> {:error, map_native_error(reason, message, path)}
    end
  end

  defp call_extract_path(path, json) do
    case Native.extract_path(path, json) do
      {:ok, bin} -> Report.decode(bin)
      {:error, reason, message} -> {:error, map_native_error(reason, message, path)}
    end
  end

  defp call_extract_bytes(bytes, name, json) do
    case Native.extract_bytes(bytes, name, json) do
      {:ok, bin} -> Report.decode(bin)
      {:error, reason, message} -> {:error, map_native_error(reason, message, name)}
    end
  end

  defp map_native_error(reason, message, path) when is_atom(reason) do
    Error.new(reason, to_string(message), path: path)
  end

  defp build_binary_input(bytes, opts) do
    Input.from_binary(bytes, opts)
  end

  defp ok_input(%Input{} = input), do: {:ok, input}
  defp ok_input({:error, _} = err), do: err

  defp project_version do
    Application.spec(:whiff, :vsn) |> to_string()
  rescue
    _ -> "0.4.0"
  end
end
