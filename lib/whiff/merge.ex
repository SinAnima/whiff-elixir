defmodule Whiff.Merge do
  @moduledoc """
  Deterministic merge of Elixir plugin patches into a native `whiff/1` report.

  Used by the plugin runner after `Whiff.Extractor` / `Whiff.Analyzer` callbacks.
  Patches must be **string-keyed** maps of JSON-safe values (maps, lists, binaries,
  numbers, booleans, `nil`). Atoms, structs, PIDs, ports, functions, and
  references are rejected.

  ## Modes (`:mode`)

  * `:augment` (default) — add missing fields; keep native scalars on conflict
  * `:fallback` — used when native did not cover the format; plugin content
    replaces native content scalars
  * `:override` — replace only paths listed in `:override_fields`

  ## Protected rules

  * Cannot patch top-level `"whiff"`, `"integrity"`, or `"embedded"`
  * Cannot replace native `"security"` keys `"risks"`, `"secrets"`, `"personal_data"`
  * `"metadata"` / `"format"` keys are namespaced; collisions error unless
    `:override` allows the path
  * `"content.keywords"` lists are concatenated and de-duplicated
  * Depth, string size, and map key count are capped

  ## Example

      iex> base = %{"content" => %{"title" => "native"}, "metadata" => %{}}
      iex> patch = %{"content" => %{"title" => "plugin", "extra" => 1}, "metadata" => %{"myapp.x" => %{"v" => 1}}}
      iex> {:ok, merged} = Whiff.Merge.merge(base, patch, mode: :augment)
      iex> merged["content"]["title"]
      "native"
      iex> merged["content"]["extra"]
      1
      iex> merged["metadata"]["myapp.x"]
      %{"v" => 1}
  """

  @max_depth 8
  @max_string 64 * 1024
  @max_map_keys 256

  @protected_top ~w(whiff integrity embedded)
  @protected_security_keys ~w(risks secrets personal_data)

  @typedoc """
  Merge strategy for conflicting keys.

  ## Example

      :augment
  """
  @type mode :: :fallback | :augment | :override

  @doc """
  Merge a plugin `patch` into `report`.

  ## Arguments

  * `report` — string-keyed `whiff/1` map
  * `patch` — string-keyed map of sections to merge
  * `opts` — optional keywords:
    * `:mode` — `t:mode/0` (default `:augment`)
    * `:override_fields` — list of path strings or bare keys allowed under
      `:override` (for example `["content.title"]` or `"title"`)
    * `:plugin_id` — id recorded in provenance / conflict details (default `"plugin"`)
    * `:provenance` — when `true`, record patched leaf paths under
      `diagnostics.provenance`

  ## Returns

  * `{:ok, report}` — merged string-keyed map
  * `{:error, %Whiff.Error{reason: :invalid_report}}` — bad shape, unsupported
    terms, depth/size limits, or `"embedded"` patch
  * `{:error, %Whiff.Error{reason: :conflict}}` — protected section or namespace
    collision without a declared override

  ## Examples

      iex> {:ok, r} = Whiff.Merge.merge(%{"content" => %{"title" => "n"}}, %{"content" => %{"title" => "p"}}, mode: :fallback)
      iex> r["content"]["title"]
      "p"

      iex> Whiff.Merge.merge(%{}, %{"embedded" => %{}}, [])
      {:error, %Whiff.Error{reason: :invalid_report, message: "embedded patches are not allowed in v0.1", path: nil, details: %{}}}

      iex> Whiff.Merge.merge(%{"whiff" => %{"schema" => "whiff/1"}}, %{"whiff" => %{}}, mode: :augment)
      {:error, %Whiff.Error{reason: :conflict, message: "cannot patch protected section `whiff`", path: nil, details: %{}}}

      iex> Whiff.Merge.merge("nope", %{}, [])
      {:error, %Whiff.Error{reason: :invalid_report, message: "merge requires map report and patch", path: nil, details: %{}}}

      iex> base = %{"metadata" => %{"native_key" => 1}}
      iex> {:ok, r} = Whiff.Merge.merge(base, %{"metadata" => %{"native_key" => 2}}, mode: :override, override_fields: ["metadata.native_key"])
      iex> r["metadata"]["native_key"]
      2
  """
  @spec merge(map(), map(), keyword()) :: {:ok, map()} | {:error, Whiff.Error.t()}
  def merge(report, patch, opts \\ [])

  def merge(report, patch, opts) when is_map(report) and is_map(patch) do
    mode = Keyword.get(opts, :mode, :augment)
    override_fields = MapSet.new(Keyword.get(opts, :override_fields, []))
    plugin_id = Keyword.get(opts, :plugin_id, "plugin")
    provenance? = Keyword.get(opts, :provenance, false)

    with :ok <- validate_patch(patch, 0),
         {:ok, report} <- apply_patch(report, patch, mode, override_fields, plugin_id) do
      report =
        if provenance? do
          append_provenance(report, patch, plugin_id)
        else
          report
        end

      {:ok, report}
    end
  end

  def merge(_, _, _) do
    {:error, Whiff.Error.new(:invalid_report, "merge requires map report and patch")}
  end

  @doc false
  def validate_patch(_value, depth) when depth > @max_depth do
    {:error, Whiff.Error.new(:invalid_report, "plugin patch exceeds max depth #{@max_depth}")}
  end

  def validate_patch(%_{}, _depth) do
    {:error, Whiff.Error.new(:invalid_report, "plugin patch must not contain structs")}
  end

  def validate_patch(map, depth) when is_map(map) do
    cond do
      map_size(map) > @max_map_keys ->
        {:error, Whiff.Error.new(:invalid_report, "plugin patch map too large")}

      not Enum.all?(Map.keys(map), &is_binary/1) ->
        {:error, Whiff.Error.new(:invalid_report, "plugin patch keys must be strings")}

      true ->
        validate_values(Map.values(map), depth + 1)
    end
  end

  def validate_patch(list, depth) when is_list(list) do
    validate_values(list, depth + 1)
  end

  def validate_patch(bin, _depth) when is_binary(bin) do
    if byte_size(bin) > @max_string do
      {:error, Whiff.Error.new(:invalid_report, "plugin patch string exceeds #{@max_string} bytes")}
    else
      :ok
    end
  end

  def validate_patch(v, _depth)
      when is_number(v) or is_boolean(v) or is_nil(v),
      do: :ok

  def validate_patch(v, _depth) when is_atom(v) do
    {:error,
     Whiff.Error.new(:invalid_report, "plugin patch must not contain atoms (got #{inspect(v)})")}
  end

  def validate_patch(v, _depth) when is_pid(v) or is_reference(v) or is_function(v) or is_port(v) do
    {:error, Whiff.Error.new(:invalid_report, "plugin patch contains unsupported term")}
  end

  def validate_patch(_, _),
    do: {:error, Whiff.Error.new(:invalid_report, "plugin patch contains unsupported value")}

  defp validate_values(values, depth) do
    Enum.reduce_while(values, :ok, fn v, :ok ->
      case validate_patch(v, depth) do
        :ok -> {:cont, :ok}
        err -> {:halt, err}
      end
    end)
  end

  defp apply_patch(report, patch, mode, override_fields, plugin_id) do
    Enum.reduce_while(patch, {:ok, report}, fn {section, value}, {:ok, acc} ->
      case merge_section(acc, section, value, mode, override_fields, plugin_id) do
        {:ok, next} -> {:cont, {:ok, next}}
        {:error, _} = err -> {:halt, err}
      end
    end)
  end

  defp merge_section(_report, "embedded", _value, _mode, _fields, _id) do
    {:error, Whiff.Error.new(:invalid_report, "embedded patches are not allowed in v0.1")}
  end

  defp merge_section(_report, section, _value, _mode, _fields, _id)
       when section in @protected_top do
    {:error, Whiff.Error.new(:conflict, "cannot patch protected section `#{section}`")}
  end

  defp merge_section(report, "security", value, mode, fields, id) when is_map(value) do
    forbidden = Map.keys(value) |> Enum.filter(&(&1 in @protected_security_keys))

    if forbidden != [] do
      {:error,
       Whiff.Error.new(:conflict, "cannot replace native security fields: #{inspect(forbidden)}")}
    else
      merge_map_section(report, "security", value, mode, fields, id)
    end
  end

  defp merge_section(report, "diagnostics", value, _mode, _fields, _id) when is_map(value) do
    existing = Map.get(report, "diagnostics") || %{}
    warnings = List.wrap(existing["warnings"]) ++ List.wrap(value["warnings"])
    limits = List.wrap(existing["limits_hit"]) ++ List.wrap(value["limits_hit"])

    merged =
      existing
      |> Map.merge(Map.drop(value, ["extractors", "warnings", "limits_hit", "provenance"]))
      |> Map.put("warnings", warnings)
      |> Map.put("limits_hit", Enum.uniq(limits))

    extractors = List.wrap(existing["extractors"]) ++ List.wrap(value["extractors"])
    merged = Map.put(merged, "extractors", extractors)
    {:ok, Map.put(report, "diagnostics", merged)}
  end

  defp merge_section(report, "content", value, mode, fields, id) when is_map(value) do
    existing = Map.get(report, "content") || %{}

    with {:ok, merged} <- merge_content(existing, value, mode, fields) do
      {:ok, Map.put(report, "content", merged)}
    end
  rescue
    e -> {:error, Whiff.Error.new(:conflict, Exception.message(e), details: %{plugin: id})}
  end

  defp merge_section(report, section, value, mode, fields, id)
       when section in ["metadata", "format"] and is_map(value) do
    existing = Map.get(report, section) || %{}

    case merge_namespaced(existing, value, mode, fields, section) do
      {:ok, merged} -> {:ok, Map.put(report, section, merged)}
      {:error, _} = err -> err
    end
  rescue
    e -> {:error, Whiff.Error.new(:conflict, Exception.message(e), details: %{plugin: id})}
  end

  defp merge_section(report, section, value, mode, fields, id) when is_map(value) do
    merge_map_section(report, section, value, mode, fields, id)
  end

  defp merge_section(_report, section, _value, _mode, _fields, _id) do
    {:error, Whiff.Error.new(:invalid_report, "unsupported patch section `#{section}`")}
  end

  defp merge_map_section(report, section, value, mode, fields, _id) do
    existing = Map.get(report, section) || %{}

    case deep_merge(existing, value, mode, fields, section) do
      {:ok, merged} -> {:ok, Map.put(report, section, merged)}
      {:error, _} = err -> err
    end
  end

  defp merge_content(existing, patch, mode, fields) do
    Enum.reduce_while(patch, {:ok, existing}, fn {k, v}, {:ok, acc} ->
      merge_content_key(acc, k, v, mode, fields)
    end)
  end

  defp merge_content_key(acc, "keywords", v, _mode, _fields) when is_list(v) do
    left = List.wrap(acc["keywords"])
    {:cont, {:ok, Map.put(acc, "keywords", Enum.uniq(left ++ v))}}
  end

  defp merge_content_key(acc, k, v, mode, fields) do
    path = "content.#{k}"

    cond do
      not Map.has_key?(acc, k) ->
        {:cont, {:ok, Map.put(acc, k, v)}}

      mode == :augment ->
        {:cont, {:ok, acc}}

      mode == :fallback ->
        {:cont, {:ok, Map.put(acc, k, v)}}

      mode == :override and override_allowed?(fields, path, k) ->
        {:cont, {:ok, Map.put(acc, k, v)}}

      mode == :override ->
        {:halt,
         {:error,
          Whiff.Error.new(:conflict, "override of `#{path}` not declared in override_fields")}}

      true ->
        {:cont, {:ok, Map.put(acc, k, v)}}
    end
  end

  defp merge_namespaced(existing, patch, mode, fields, section) do
    Enum.reduce_while(patch, {:ok, existing}, fn {k, v}, {:ok, acc} ->
      path = "#{section}.#{k}"

      cond do
        Map.has_key?(acc, k) and mode == :override and override_allowed?(fields, path, k) ->
          {:cont, {:ok, Map.put(acc, k, v)}}

        Map.has_key?(acc, k) ->
          {:halt, {:error, Whiff.Error.new(:conflict, "namespace collision on `#{path}`")}}

        true ->
          {:cont, {:ok, Map.put(acc, k, v)}}
      end
    end)
  end

  defp deep_merge(existing, patch, mode, fields, prefix) when is_map(existing) and is_map(patch) do
    Enum.reduce_while(patch, {:ok, existing}, fn {k, v}, {:ok, acc} ->
      deep_merge_key(acc, k, v, mode, fields, prefix)
    end)
  end

  defp deep_merge_key(acc, k, v, mode, fields, prefix) do
    path = "#{prefix}.#{k}"

    case Map.fetch(acc, k) do
      :error -> {:cont, {:ok, Map.put(acc, k, v)}}
      {:ok, existing} -> resolve_existing_key(acc, k, existing, v, mode, fields, path)
    end
  end

  defp resolve_existing_key(acc, k, existing, v, mode, fields, path)
       when is_map(existing) and is_map(v) do
    case deep_merge(existing, v, mode, fields, path) do
      {:ok, merged} -> {:cont, {:ok, Map.put(acc, k, merged)}}
      err -> {:halt, err}
    end
  end

  defp resolve_existing_key(acc, k, _existing, v, :override, fields, path) do
    if override_allowed?(fields, path, k) do
      {:cont, {:ok, Map.put(acc, k, v)}}
    else
      {:halt, {:error, Whiff.Error.new(:conflict, "collision on `#{path}`")}}
    end
  end

  defp resolve_existing_key(acc, _k, _existing, _v, _mode, _fields, _path) do
    {:cont, {:ok, acc}}
  end

  defp override_allowed?(fields, path, k) do
    MapSet.member?(fields, path) or MapSet.member?(fields, k)
  end

  defp append_provenance(report, patch, plugin_id) do
    diagnostics = Map.get(report, "diagnostics") || %{}
    provenance = Map.get(diagnostics, "provenance") || %{}

    paths =
      patch
      |> flatten_paths()
      |> Map.new(fn path -> {path, %{"source" => "elixir:#{plugin_id}"}} end)

    provenance = Map.merge(provenance, paths, fn _k, native, _elixir -> native end)
    diagnostics = Map.put(diagnostics, "provenance", provenance)
    Map.put(report, "diagnostics", diagnostics)
  end

  defp flatten_paths(map, prefix \\ nil)

  defp flatten_paths(map, prefix) when is_map(map) do
    Enum.flat_map(map, fn {k, v} ->
      path = if prefix, do: "#{prefix}.#{k}", else: k

      if is_map(v) do
        flatten_paths(v, path)
      else
        [path]
      end
    end)
  end
end
