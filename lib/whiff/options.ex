defmodule Whiff.Options do
  @moduledoc false

  # Validates public options before any native call.
  #
  # Each public entry point has its own allow-list, so an option that a
  # function would ignore is rejected instead of silently dropped.

  alias Whiff.Error

  @native_keys ~w(profile hashes privacy only skip format provenance limits)a
  @pipeline_keys ~w(extractors analyzers mode strict plugin_timeout_ms override_fields)a

  @allowed %{
    extract: @native_keys ++ @pipeline_keys ++ [:stage],
    extract_binary: @native_keys ++ @pipeline_keys ++ [:name, :filename, :mime],
    llm: @native_keys ++ [:tokens, :stage],
    extract_many: @native_keys ++ @pipeline_keys ++ [:stage, :max_concurrency, :on_error, :timeout]
  }

  @profiles ~w(minimal standard full llm)a
  @privacy ~w(strict off)a
  @modes ~w(fallback augment override)a
  @stages ~w(never local)a

  # Mirrors LIMIT_CAPS in native/whiff_native/src/lib.rs. A test compares both.
  @limit_caps %{
    max_read_bytes: 4 * 1024 * 1024 * 1024,
    max_decompressed_bytes: 4 * 1024 * 1024 * 1024,
    max_depth: 8,
    max_children: 500,
    file_timeout_ms: 600_000,
    extractor_timeout_ms: 600_000,
    max_text_bytes: 64 * 1024 * 1024,
    hash_max_bytes: 4 * 1024 * 1024 * 1024,
    max_parse_bytes: 256 * 1024 * 1024
  }

  # Zero has no useful meaning for these upstream limits.
  @nonzero_limits ~w(max_read_bytes max_decompressed_bytes file_timeout_ms extractor_timeout_ms)a

  @callbacks %{
    extractors: [id: 0, version: 0, supports?: 2, extract: 2],
    analyzers: [id: 0, version: 0, analyze: 2]
  }

  @type entry :: :extract | :extract_binary | :llm | :extract_many

  @doc "Upper caps for `:limits` keys."
  @spec limit_caps() :: %{atom() => pos_integer()}
  def limit_caps, do: @limit_caps

  @doc """
  Validate and normalize keyword options for one public entry point.
  """
  @spec validate(term(), entry()) :: {:ok, map()} | {:error, Error.t()}
  def validate(opts, entry \\ :extract)

  def validate(opts, entry) when is_list(opts) and is_map_key(@allowed, entry) do
    if Keyword.keyword?(opts) do
      with :ok <- reject_unknown(opts, Map.fetch!(@allowed, entry)),
           :ok <- reject_duplicates(opts),
           :ok <- reject_name_and_filename(opts) do
        normalize(opts)
      end
    else
      {:error, Error.new(:invalid_option, "options must be a keyword list")}
    end
  end

  def validate(_opts, _entry) do
    {:error, Error.new(:invalid_option, "options must be a keyword list")}
  end

  @doc """
  Validate a list of plugin modules (`kind` is `:extractors` or `:analyzers`).

  Every module must be loaded and export the behaviour's callbacks.
  """
  @spec validate_modules(term(), :extractors | :analyzers) ::
          {:ok, [module()]} | {:error, Error.t()}
  def validate_modules(list, kind) when is_list(list) do
    case Enum.reject(list, &implements?(&1, kind)) do
      [] ->
        {:ok, list}

      bad ->
        {:error,
         Error.new(
           :invalid_option,
           "#{kind} must implement #{behaviour_name(kind)}: #{inspect(bad)}",
           details: %{invalid: bad}
         )}
    end
  end

  def validate_modules(_other, kind) do
    {:error, Error.new(:invalid_option, "#{kind} must be a list of modules")}
  end

  @doc "JSON payload for the NIF (native keys only)."
  @spec to_native_json(map()) :: String.t()
  def to_native_json(opts) when is_map(opts) do
    opts
    |> Map.take(@native_keys ++ [:tokens])
    |> Enum.reject(fn {_k, v} -> is_nil(v) end)
    |> Map.new(fn {k, v} -> {Atom.to_string(k), encode_value(v)} end)
    |> Jason.encode!()
  end

  defp implements?(mod, kind) when is_atom(mod) do
    Code.ensure_loaded?(mod) and
      Enum.all?(Map.fetch!(@callbacks, kind), fn {fun, arity} ->
        function_exported?(mod, fun, arity)
      end)
  end

  defp implements?(_mod, _kind), do: false

  defp behaviour_name(:extractors), do: "Whiff.Extractor"
  defp behaviour_name(:analyzers), do: "Whiff.Analyzer"

  defp reject_unknown(opts, allowed) do
    case opts |> Keyword.keys() |> Enum.reject(&(&1 in allowed)) |> Enum.uniq() do
      [] ->
        :ok

      keys ->
        {:error,
         Error.new(:invalid_option, "unknown option(s): #{inspect(keys)}",
           details: %{unknown: keys}
         )}
    end
  end

  defp reject_duplicates(opts) do
    case opts |> Keyword.keys() |> then(&(&1 -- Enum.uniq(&1))) |> Enum.uniq() do
      [] ->
        :ok

      keys ->
        {:error,
         Error.new(:invalid_option, "duplicate option(s): #{inspect(keys)}",
           details: %{duplicate: keys}
         )}
    end
  end

  defp reject_name_and_filename(opts) do
    if Keyword.has_key?(opts, :name) and Keyword.has_key?(opts, :filename) do
      {:error, Error.new(:invalid_option, "pass either :name or :filename, not both")}
    else
      :ok
    end
  end

  defp normalize(opts) do
    base = %{
      profile: :standard,
      privacy: :strict,
      mode: :fallback,
      strict: false,
      plugin_timeout_ms: 5_000,
      provenance: false,
      tokens: 800,
      stage: :never
    }

    Enum.reduce_while(opts, {:ok, base}, fn {key, value}, {:ok, acc} ->
      case normalize_one(key, value) do
        {:ok, v} -> {:cont, {:ok, Map.put(acc, key, v)}}
        {:error, _} = err -> {:halt, err}
      end
    end)
  end

  defp normalize_one(:profile, v) when v in @profiles, do: {:ok, v}
  defp normalize_one(:privacy, v) when v in @privacy, do: {:ok, v}
  defp normalize_one(:mode, v) when v in @modes, do: {:ok, v}
  defp normalize_one(:stage, v) when v in @stages, do: {:ok, v}
  defp normalize_one(:on_error, v) when v in [:collect, :halt], do: {:ok, v}
  defp normalize_one(:hashes, v) when v in [:all, :none], do: {:ok, v}

  defp normalize_one(:hashes, list) when is_list(list) and list != [] do
    if Enum.all?(list, &(&1 in [:sha256, :blake3])),
      do: {:ok, Enum.uniq(list)},
      else: invalid(:hashes, list, "be :all, :none, or a non-empty list of :sha256 / :blake3")
  end

  defp normalize_one(key, list) when key in [:only, :skip] and is_list(list) do
    if Enum.all?(list, &non_empty_string?/1),
      do: {:ok, list},
      else: invalid(key, list, "be a list of extractor id strings")
  end

  defp normalize_one(:override_fields, list) when is_list(list) do
    if Enum.all?(list, &dotted_path?/1),
      do: {:ok, list},
      else: invalid(:override_fields, list, ~s(be a list of dotted paths such as "content.title"))
  end

  defp normalize_one(key, v) when key in [:format, :name, :filename, :mime] do
    if non_empty_string?(v), do: {:ok, v}, else: invalid(key, v, "be a non-empty string")
  end

  defp normalize_one(key, v) when key in [:provenance, :strict] and is_boolean(v), do: {:ok, v}

  defp normalize_one(:tokens, n) when is_integer(n) and n in 1..100_000, do: {:ok, n}
  defp normalize_one(:plugin_timeout_ms, n) when is_integer(n) and n in 1..600_000, do: {:ok, n}
  defp normalize_one(:max_concurrency, n) when is_integer(n) and n in 1..128, do: {:ok, n}
  defp normalize_one(:timeout, n) when is_integer(n) and n in 1..3_600_000, do: {:ok, n}
  defp normalize_one(:timeout, :infinity), do: {:ok, :infinity}

  defp normalize_one(:limits, list) when is_list(list), do: validate_limits(list)

  defp normalize_one(kind, list) when kind in [:extractors, :analyzers],
    do: validate_modules(list, kind)

  defp normalize_one(key, v), do: invalid(key, v, expectation(key))

  defp expectation(:profile), do: "be one of #{inspect(@profiles)}"
  defp expectation(:privacy), do: "be :strict or :off"
  defp expectation(:mode), do: "be one of #{inspect(@modes)}"
  defp expectation(:stage), do: "be :never or :local"
  defp expectation(:on_error), do: "be :collect or :halt"
  defp expectation(:hashes), do: "be :all, :none, or a non-empty list of :sha256 / :blake3"
  defp expectation(key) when key in [:only, :skip], do: "be a list of extractor id strings"
  defp expectation(:override_fields), do: ~s(be a list of dotted paths such as "content.title")
  defp expectation(key) when key in [:provenance, :strict], do: "be a boolean"
  defp expectation(:tokens), do: "be an integer in 1..100000"
  defp expectation(:plugin_timeout_ms), do: "be an integer in 1..600000"
  defp expectation(:max_concurrency), do: "be an integer in 1..128"
  defp expectation(:timeout), do: "be an integer in 1..3600000 or :infinity"
  defp expectation(:limits), do: "be a keyword list"

  defp invalid(key, value, expectation) do
    {:error,
     Error.new(:invalid_option, "#{key} must #{expectation}, got: #{inspect(value, limit: 5)}")}
  end

  defp validate_limits(list) do
    cond do
      not Keyword.keyword?(list) ->
        invalid(:limits, list, "be a keyword list")

      (unknown = Keyword.keys(list) -- Map.keys(@limit_caps)) != [] ->
        {:error, Error.new(:invalid_option, "unknown limit key(s): #{inspect(unknown)}")}

      true ->
        Enum.reduce_while(list, {:ok, %{}}, &put_limit/2)
    end
  end

  defp put_limit({k, v}, {:ok, acc}) do
    case validate_limit(k, v) do
      :ok -> {:cont, {:ok, Map.put(acc, k, v)}}
      {:error, _} = err -> {:halt, err}
    end
  end

  defp validate_limit(key, v) when is_integer(v) and v >= 0 do
    cap = Map.fetch!(@limit_caps, key)

    cond do
      v == 0 and key in @nonzero_limits ->
        {:error, Error.new(:invalid_option, "#{key} must be greater than 0")}

      v > cap ->
        {:error, Error.new(:invalid_option, "#{key} exceeds cap #{cap}")}

      true ->
        :ok
    end
  end

  defp validate_limit(key, v),
    do:
      {:error,
       Error.new(:invalid_option, "#{key} must be a non-negative integer, got: #{inspect(v)}")}

  defp non_empty_string?(v), do: is_binary(v) and v != ""

  defp dotted_path?(v) do
    is_binary(v) and match?([_, _ | _], String.split(v, ".")) and
      not Enum.any?(String.split(v, "."), &(&1 == ""))
  end

  defp encode_value(v) when is_boolean(v), do: v
  defp encode_value(v) when is_atom(v), do: Atom.to_string(v)
  defp encode_value(list) when is_list(list), do: Enum.map(list, &encode_value/1)

  defp encode_value(map) when is_map(map),
    do: Map.new(map, fn {k, v} -> {to_string(k), encode_value(v)} end)

  defp encode_value(v), do: v
end
