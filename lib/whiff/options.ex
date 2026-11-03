defmodule Whiff.Options do
  @moduledoc false

  @known_keys ~w(
    profile hashes privacy only skip format provenance limits tokens
    extractors analyzers mode strict plugin_timeout_ms max_concurrency on_error
    name filename mime override_fields stage
  )a

  @profiles ~w(minimal standard full llm)a
  @privacy ~w(strict off)a
  @modes ~w(fallback augment override)a
  @stages ~w(never local)a

  @limit_keys ~w(
    max_read_bytes max_decompressed_bytes max_depth max_children
    file_timeout_ms extractor_timeout_ms max_text_bytes hash_max_bytes max_parse_bytes
  )a

  @limit_caps %{
    max_read_bytes: 4 * 1024 * 1024 * 1024,
    max_decompressed_bytes: 4 * 1024 * 1024 * 1024,
    max_depth: 8,
    max_children: 500,
    file_timeout_ms: 600_000,
    extractor_timeout_ms: 600_000
  }

  @type t :: %{
          optional(atom()) => term()
        }

  @doc """
  Validate and normalize keyword options for public APIs.
  """
  @spec validate(keyword()) :: {:ok, map()} | {:error, Whiff.Error.t()}
  def validate(opts) when is_list(opts) do
    with :ok <- reject_unknown(opts),
         {:ok, opts} <- normalize(opts) do
      {:ok, opts}
    end
  end

  def validate(_) do
    {:error, Whiff.Error.new(:invalid_option, "options must be a keyword list")}
  end

  @doc """
  JSON payload for the NIF (native-relevant keys only).
  """
  @spec to_native_json(map()) :: String.t()
  def to_native_json(opts) when is_map(opts) do
    native =
      opts
      |> Map.take([
        :profile,
        :hashes,
        :privacy,
        :only,
        :skip,
        :format,
        :provenance,
        :limits,
        :tokens
      ])
      |> Enum.reject(fn {_k, v} -> is_nil(v) end)
      |> Map.new(fn {k, v} -> {Atom.to_string(k), encode_value(v)} end)

    Jason.encode!(native)
  end

  defp reject_unknown(opts) do
    unknown =
      opts
      |> Keyword.keys()
      |> Enum.reject(&(&1 in @known_keys))

    case unknown do
      [] ->
        :ok

      keys ->
        {:error,
         Whiff.Error.new(:invalid_option, "unknown option(s): #{inspect(keys)}",
           details: %{unknown: keys}
         )}
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
        {:ok, nil} -> {:cont, {:ok, acc}}
        {:ok, v} -> {:cont, {:ok, Map.put(acc, key, v)}}
        {:error, _} = err -> {:halt, err}
      end
    end)
  end

  defp normalize_one(:profile, v) when v in @profiles, do: {:ok, v}

  defp normalize_one(:profile, v),
    do: {:error, Whiff.Error.new(:invalid_option, "invalid profile: #{inspect(v)}")}

  defp normalize_one(:privacy, v) when v in @privacy, do: {:ok, v}

  defp normalize_one(:privacy, v),
    do: {:error, Whiff.Error.new(:invalid_option, "invalid privacy: #{inspect(v)}")}

  defp normalize_one(:mode, v) when v in @modes, do: {:ok, v}

  defp normalize_one(:mode, v),
    do: {:error, Whiff.Error.new(:invalid_option, "invalid mode: #{inspect(v)}")}

  defp normalize_one(:hashes, :all), do: {:ok, :all}
  defp normalize_one(:hashes, :none), do: {:ok, :none}

  defp normalize_one(:hashes, list) when is_list(list) do
    if Enum.all?(list, &(&1 in [:sha256, :blake3])) do
      {:ok, list}
    else
      {:error, Whiff.Error.new(:invalid_option, "invalid hashes list: #{inspect(list)}")}
    end
  end

  defp normalize_one(:hashes, v),
    do: {:error, Whiff.Error.new(:invalid_option, "invalid hashes: #{inspect(v)}")}

  defp normalize_one(:only, list) when is_list(list) do
    if Enum.all?(list, &is_binary/1) do
      {:ok, list}
    else
      {:error,
       Whiff.Error.new(:invalid_option, "only must be a list of strings, got: #{inspect(list)}")}
    end
  end

  defp normalize_one(:only, v),
    do:
      {:error,
       Whiff.Error.new(:invalid_option, "only must be a list of strings, got: #{inspect(v)}")}

  defp normalize_one(:skip, list) when is_list(list) do
    if Enum.all?(list, &is_binary/1) do
      {:ok, list}
    else
      {:error,
       Whiff.Error.new(:invalid_option, "skip must be a list of strings, got: #{inspect(list)}")}
    end
  end

  defp normalize_one(:skip, v),
    do:
      {:error,
       Whiff.Error.new(:invalid_option, "skip must be a list of strings, got: #{inspect(v)}")}

  defp normalize_one(:format, v) when is_binary(v), do: {:ok, v}

  defp normalize_one(:format, v),
    do: {:error, Whiff.Error.new(:invalid_option, "format must be a string, got: #{inspect(v)}")}

  defp normalize_one(:provenance, v) when is_boolean(v), do: {:ok, v}

  defp normalize_one(:provenance, v),
    do: {:error, Whiff.Error.new(:invalid_option, "provenance must be boolean, got: #{inspect(v)}")}

  defp normalize_one(:strict, v) when is_boolean(v), do: {:ok, v}

  defp normalize_one(:strict, v),
    do: {:error, Whiff.Error.new(:invalid_option, "strict must be boolean, got: #{inspect(v)}")}

  defp normalize_one(:tokens, n) when is_integer(n) and n > 0 and n <= 100_000, do: {:ok, n}

  defp normalize_one(:tokens, v),
    do: {:error, Whiff.Error.new(:invalid_option, "tokens must be 1..100000, got: #{inspect(v)}")}

  defp normalize_one(:plugin_timeout_ms, n) when is_integer(n) and n > 0 and n <= 600_000,
    do: {:ok, n}

  defp normalize_one(:plugin_timeout_ms, v),
    do:
      {:error,
       Whiff.Error.new(:invalid_option, "plugin_timeout_ms must be 1..600000, got: #{inspect(v)}")}

  defp normalize_one(:max_concurrency, n) when is_integer(n) and n > 0 and n <= 128, do: {:ok, n}

  defp normalize_one(:max_concurrency, v),
    do:
      {:error,
       Whiff.Error.new(:invalid_option, "max_concurrency must be 1..128, got: #{inspect(v)}")}

  defp normalize_one(:on_error, v) when v in [:collect, :halt], do: {:ok, v}

  defp normalize_one(:on_error, v),
    do:
      {:error,
       Whiff.Error.new(:invalid_option, "on_error must be :collect or :halt, got: #{inspect(v)}")}

  defp normalize_one(:stage, v) when v in @stages, do: {:ok, v}

  defp normalize_one(:stage, v),
    do:
      {:error,
       Whiff.Error.new(:invalid_option, "stage must be :never or :local, got: #{inspect(v)}")}

  defp normalize_one(:limits, list) when is_list(list), do: validate_limits(list)

  defp normalize_one(:limits, v),
    do:
      {:error,
       Whiff.Error.new(:invalid_option, "limits must be a keyword list, got: #{inspect(v)}")}

  defp normalize_one(:extractors, list) when is_list(list) do
    if Enum.all?(list, &is_atom/1) do
      {:ok, list}
    else
      {:error, Whiff.Error.new(:invalid_option, "extractors must be a list of modules")}
    end
  end

  defp normalize_one(:extractors, _v),
    do: {:error, Whiff.Error.new(:invalid_option, "extractors must be a list of modules")}

  defp normalize_one(:analyzers, list) when is_list(list) do
    if Enum.all?(list, &is_atom/1) do
      {:ok, list}
    else
      {:error, Whiff.Error.new(:invalid_option, "analyzers must be a list of modules")}
    end
  end

  defp normalize_one(:analyzers, _v),
    do: {:error, Whiff.Error.new(:invalid_option, "analyzers must be a list of modules")}

  defp normalize_one(:override_fields, list) when is_list(list) do
    if Enum.all?(list, &is_binary/1) do
      {:ok, list}
    else
      {:error, Whiff.Error.new(:invalid_option, "override_fields must be a list of field paths")}
    end
  end

  defp normalize_one(:override_fields, _v),
    do: {:error, Whiff.Error.new(:invalid_option, "override_fields must be a list of field paths")}

  defp normalize_one(:name, v) when is_binary(v), do: {:ok, v}
  defp normalize_one(:filename, v) when is_binary(v), do: {:ok, v}
  defp normalize_one(:mime, v) when is_binary(v), do: {:ok, v}

  defp normalize_one(key, v),
    do: {:error, Whiff.Error.new(:invalid_option, "invalid #{key}: #{inspect(v)}")}

  defp validate_limits(list) do
    unknown = Keyword.keys(list) -- @limit_keys

    if unknown != [] do
      {:error, Whiff.Error.new(:invalid_option, "unknown limit key(s): #{inspect(unknown)}")}
    else
      reduce_limits(list)
    end
  end

  defp reduce_limits(list) do
    Enum.reduce_while(list, {:ok, %{}}, fn {k, v}, {:ok, acc} ->
      case validate_limit(k, v) do
        {:ok, val} -> {:cont, {:ok, Map.put(acc, k, val)}}
        {:error, _} = err -> {:halt, err}
      end
    end)
  end

  defp validate_limit(key, v) when is_integer(v) and v >= 0 do
    cap = Map.get(@limit_caps, key)

    if cap && v > cap do
      {:error, Whiff.Error.new(:invalid_option, "#{key} exceeds cap #{cap}")}
    else
      {:ok, v}
    end
  end

  defp validate_limit(key, v),
    do: {:error, Whiff.Error.new(:invalid_option, "invalid #{key}: #{inspect(v)}")}

  defp encode_value(v) when is_boolean(v), do: v
  defp encode_value(v) when is_atom(v), do: Atom.to_string(v)
  defp encode_value(list) when is_list(list), do: Enum.map(list, &encode_value/1)

  defp encode_value(map) when is_map(map) do
    Map.new(map, fn {k, v} -> {to_string(k), encode_value(v)} end)
  end

  defp encode_value(v), do: v
end
