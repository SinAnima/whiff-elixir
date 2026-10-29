defmodule Whiff do
  @moduledoc """
  Elixir wrapper around the Rust [whiff](https://github.com/baoulo/whiff) crate.

  Returns idiomatic `{:ok, report}` / `{:error, %Whiff.Error{}}` results where
  `report` is a **string-keyed** map conforming to schema `whiff/1`.

  ## Examples

      iex> is_binary(Whiff.schema_version())
      true

  Native identification/extraction is the default. Elixir extractors
  (`Whiff.Extractor`) and analyzers (`Whiff.Analyzer`) run in BEAM processes
  outside the NIF.
  """

  alias Whiff.{Error, Input, Limiter, Native, Options, Registry, Report}

  @type report :: %{optional(String.t()) => term()}
  @type result :: {:ok, report()} | {:error, Error.t()}

  @doc "Library version."
  @spec version() :: String.t()
  def version, do: project_version()

  @doc "Report schema version (`whiff/1`)."
  @spec schema_version() :: String.t()
  def schema_version, do: Report.schema_version()

  @doc """
  Extract a `whiff/1` report from a filesystem path.

  ## Options

  Native: `:profile`, `:hashes`, `:privacy`, `:only`, `:skip`, `:format`,
  `:provenance`, `:limits`, `:tokens` (llm only).

  Pipeline: `:mode` (`:fallback` | `:augment` | `:override`), `:extractors`,
  `:analyzers`, `:strict`, `:plugin_timeout_ms`, `:override_fields`.
  """
  @spec extract(Path.t(), keyword()) :: result()
  def extract(path, opts \\ [])

  def extract(path, opts) when is_binary(path) and is_list(opts) do
    with {:ok, options} <- Options.validate(opts),
         input = Input.from_path(path),
         {:ok, report} <- native_extract_path(path, options) do
      Registry.run(input, report, options)
    end
  end

  def extract(_, _) do
    {:error, Error.new(:unsupported_input, "path must be a binary")}
  end

  @doc "Same as `extract/2` but raises `Whiff.Error`."
  @spec extract!(Path.t(), keyword()) :: report()
  def extract!(path, opts \\ []) do
    case extract(path, opts) do
      {:ok, report} -> report
      {:error, %Error{} = err} -> raise err
    end
  end

  @doc """
  Extract from in-memory bytes.

  Pass `name:` (filename) to aid detection.
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

  @doc "Same as `extract_binary/2` but raises `Whiff.Error`."
  @spec extract_binary!(binary(), keyword()) :: report()
  def extract_binary!(bytes, opts \\ []) do
    case extract_binary(bytes, opts) do
      {:ok, report} -> report
      {:error, %Error{} = err} -> raise err
    end
  end

  @doc """
  Compact LLM projection for a path (`Report::llm_view`).

  Default token budget: `800` (override with `tokens:`).
  """
  @spec llm(Path.t(), keyword()) :: result()
  def llm(path, opts \\ [])

  def llm(path, opts) when is_binary(path) and is_list(opts) do
    with {:ok, options} <- Options.validate(opts) do
      json = Options.to_native_json(options)
      Limiter.with_native(fn -> call_llm_path(path, json) end)
    end
  end

  def llm(_, _), do: {:error, Error.new(:unsupported_input, "path must be a binary")}

  @doc "Same as `llm/2` but raises `Whiff.Error`."
  @spec llm!(Path.t(), keyword()) :: report()
  def llm!(path, opts \\ []) do
    case llm(path, opts) do
      {:ok, report} -> report
      {:error, %Error{} = err} -> raise err
    end
  end

  @doc """
  Extract many paths with bounded concurrency.

  Returns a list of `{path, result}` in input order.

  Options: `:max_concurrency` (default 4), `:on_error` (`:collect` | `:halt`).
  Other options are forwarded to `extract/2`.
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

  # Mix.Project may be unavailable at runtime in a release — fall back.
  defp project_version do
    Application.spec(:whiff, :vsn) |> to_string()
  rescue
    _ -> "0.1.0"
  end
end
