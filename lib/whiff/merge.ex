defmodule Whiff.Merge do
  @moduledoc """
  Deterministic merge of Elixir plugin patches into a `whiff/1` report.

  The plugin pipeline calls this after each `Whiff.Extractor` or
  `Whiff.Analyzer` callback. You can also call `merge/3` directly to test a
  plugin's patch.

  ## Patch shape

  A patch is a string-keyed map whose top-level keys are report sections.
  Values are JSON-safe: maps with string keys, lists, binaries, numbers,
  booleans, and `nil`. Atoms, structs, PIDs, ports, functions, and references
  are rejected.

  Size limits (exceeding any returns `:invalid_report`):

  | Limit | Value |
  |---|---|
  | nesting depth | 8 |
  | keys per map | 256 |
  | bytes per string | 65,536 |
  | total values (maps, lists, scalars) | 10,000 |
  | total string bytes | 1,048,576 |

  ## Section rules

  | Section | Rule |
  |---|---|
  | `whiff`, `integrity` | rejected (`:conflict`) |
  | `embedded` | rejected (`:invalid_report`) |
  | `diagnostics` | only `warnings` (list of strings); each is prefixed with `"elixir:<plugin_id>: "` |
  | `security` | `risks` entries are appended after validation, with `source` set to `"elixir:<plugin_id>"`; `secrets` and `personal_data` are rejected; other keys may be added but never replace a native value |
  | `metadata`, `format` | each top-level key is a namespace (for example `"myapp.trade"`); an existing namespace is a conflict unless `:override` declares `"<section>.<key>"` |
  | `content` | `keywords` are appended and de-duplicated; other fields follow the mode rules below |
  | `source`, `identification`, `system`, `temporal`, `rights`, `physical` | nested maps merge; leaves follow the mode rules below |
  | any other key | rejected (`:invalid_report`) |

  ## Mode rules for an existing leaf value

  | Existing value set by | `:augment` | `:fallback` | `:override` |
  |---|---|---|---|
  | native | kept | kept, except `content.*` which is replaced | replaced if the path is in `:override_fields`, otherwise `:conflict` |
  | another plugin in the same call | `:conflict` | `:conflict` | replaced if declared, otherwise `:conflict` |

  An identical value is never a conflict. Missing values are always added.

  ## Provenance

  With `provenance: true`, every path this patch wrote is recorded in
  `diagnostics.provenance` as `"<path>" => "elixir:<plugin_id>"`, the same
  path-to-source string shape upstream uses. Existing entries are kept.

  ## Example

      iex> base = %{"content" => %{"title" => "native"}, "metadata" => %{}}
      iex> patch = %{"content" => %{"title" => "plugin", "extra" => 1}, "metadata" => %{"myapp.x" => %{"v" => 1}}}
      iex> {:ok, merged} = Whiff.Merge.merge(base, patch, mode: :augment)
      iex> {merged["content"]["title"], merged["content"]["extra"], merged["metadata"]["myapp.x"]}
      {"native", 1, %{"v" => 1}}
  """

  @max_depth 8
  @max_string 64 * 1024
  @max_map_keys 256
  @max_nodes 10_000
  @max_total_bytes 1024 * 1024

  @schema_path Path.expand("../../priv/schemas/whiff-1.schema.json", __DIR__)
  @external_resource @schema_path
  @schema_defs @schema_path |> File.read!() |> Jason.decode!() |> Map.fetch!("$defs")
  @risk_categories for %{"const" => c} <- @schema_defs["RiskCategory"]["oneOf"], do: c
  @severities for %{"const" => c} <- @schema_defs["Severity"]["oneOf"], do: c
  @risk_keys ~w(kind category severity detail source)

  @tree_sections ~w(source identification system temporal rights physical)
  @namespaced_sections ~w(metadata format)

  @typedoc """
  Merge strategy for existing values. See the moduledoc table.

  ## Example

      :augment
  """
  @type mode :: :fallback | :augment | :override

  @typedoc """
  Merge options.

  * `:mode` — `t:mode/0` (default `:augment`)
  * `:override_fields` — dotted paths that `:override` may replace, for example
    `["content.title", "format.myapp.trade"]` (default `[]`)
  * `:plugin_id` — id recorded in provenance and warnings (default `"plugin"`)
  * `:provenance` — record written paths in `diagnostics.provenance` (default `false`)
  * `:owned` — `MapSet` of paths written by earlier plugins in the same call
    (default empty); used by the pipeline to detect plugin-to-plugin conflicts

  ## Example

      [mode: :override, override_fields: ["content.title"], plugin_id: "myapp.trade"]
  """
  @type opts :: [
          mode: mode(),
          override_fields: [String.t()],
          plugin_id: String.t(),
          provenance: boolean(),
          owned: MapSet.t(String.t())
        ]

  @doc """
  Merge a plugin `patch` into `report`.

  ## Arguments

  * `report` — string-keyed `whiff/1` map
  * `patch` — string-keyed map of sections (see the moduledoc)
  * `opts` — `t:opts/0`

  ## Returns

  * `{:ok, report}`
  * `{:error, %Whiff.Error{reason: :invalid_report}}` — unsupported term, size
    limit, unknown section, `embedded` patch, or invalid risk entry
  * `{:error, %Whiff.Error{reason: :conflict}}` — protected section, existing
    namespace, undeclared override, or another plugin's value

  ## Examples

  `:fallback` replaces native `content` scalars:

      iex> {:ok, r} = Whiff.Merge.merge(%{"content" => %{"title" => "n"}}, %{"content" => %{"title" => "p"}}, mode: :fallback)
      iex> r["content"]["title"]
      "p"

  `:override` replaces only declared paths:

      iex> base = %{"metadata" => %{"native.key" => 1}}
      iex> {:ok, r} = Whiff.Merge.merge(base, %{"metadata" => %{"native.key" => 2}}, mode: :override, override_fields: ["metadata.native.key"])
      iex> r["metadata"]["native.key"]
      2
      iex> {:error, err} = Whiff.Merge.merge(base, %{"metadata" => %{"native.key" => 2}}, mode: :override)
      iex> err.reason
      :conflict

  Risks are appended with a source:

      iex> {:ok, r} = Whiff.Merge.merge(%{"security" => %{"risks" => []}},
      ...>   %{"security" => %{"risks" => [%{"kind" => "macros", "category" => "active_content", "severity" => "high"}]}},
      ...>   plugin_id: "myapp.scan")
      iex> hd(r["security"]["risks"])["source"]
      "elixir:myapp.scan"

  Errors:

      iex> Whiff.Merge.merge(%{}, %{"embedded" => %{}})
      {:error, %Whiff.Error{reason: :invalid_report, message: "embedded patches are not allowed", path: nil, details: %{}}}

      iex> Whiff.Merge.merge(%{"whiff" => %{"schema" => "whiff/1"}}, %{"whiff" => %{}})
      {:error, %Whiff.Error{reason: :conflict, message: "cannot patch protected section `whiff`", path: nil, details: %{}}}

      iex> Whiff.Merge.merge(%{}, %{"plugins" => %{}})
      {:error, %Whiff.Error{reason: :invalid_report, message: "unsupported patch section `plugins`", path: nil, details: %{}}}

      iex> Whiff.Merge.merge("nope", %{})
      {:error, %Whiff.Error{reason: :invalid_report, message: "merge requires map report and patch", path: nil, details: %{}}}
  """
  @spec merge(map(), map(), opts()) :: {:ok, map()} | {:error, Whiff.Error.t()}
  def merge(report, patch, opts \\ []) do
    with {:ok, merged, _written} <- merge_tracked(report, patch, opts), do: {:ok, merged}
  end

  @doc false
  # Same as merge/3 but also returns the list of paths this patch wrote.
  @spec merge_tracked(map(), map(), opts()) ::
          {:ok, map(), [String.t()]} | {:error, Whiff.Error.t()}
  def merge_tracked(report, patch, opts \\ [])

  def merge_tracked(report, patch, opts) when is_map(report) and is_map(patch) do
    ctx = %{
      mode: Keyword.get(opts, :mode, :augment),
      fields: MapSet.new(Keyword.get(opts, :override_fields, [])),
      id: Keyword.get(opts, :plugin_id, "plugin"),
      owned: Keyword.get(opts, :owned, MapSet.new())
    }

    with :ok <- validate_patch(patch),
         {:ok, merged, written} <- apply_sections(report, patch, ctx) do
      merged =
        if Keyword.get(opts, :provenance, false),
          do: append_provenance(merged, written, ctx.id),
          else: merged

      {:ok, merged, written}
    end
  end

  def merge_tracked(_, _, _) do
    {:error, Whiff.Error.new(:invalid_report, "merge requires map report and patch")}
  end

  @doc """
  Check a patch against the term and size limits in the moduledoc.

  ## Examples

      iex> Whiff.Merge.validate_patch(%{"content" => %{"keywords" => ["a", 1, true, nil]}})
      :ok

      iex> Whiff.Merge.validate_patch(%{"content" => %{"title" => :atom}})
      {:error, %Whiff.Error{reason: :invalid_report, message: "plugin patch must not contain atoms (got :atom)", path: nil, details: %{}}}
  """
  @spec validate_patch(term()) :: :ok | {:error, Whiff.Error.t()}
  def validate_patch(patch) do
    case walk_size(patch, 0, {0, 0}) do
      {:ok, _} -> :ok
      {:error, _} = err -> err
    end
  end

  defp walk_size(_value, depth, _acc) when depth > @max_depth,
    do: invalid("plugin patch exceeds max depth #{@max_depth}")

  defp walk_size(_value, _depth, {nodes, _}) when nodes >= @max_nodes,
    do: invalid("plugin patch exceeds #{@max_nodes} values")

  defp walk_size(%_{}, _depth, _acc), do: invalid("plugin patch must not contain structs")

  defp walk_size(map, depth, {nodes, bytes}) when is_map(map) do
    cond do
      map_size(map) > @max_map_keys ->
        invalid("plugin patch map exceeds #{@max_map_keys} keys")

      not Enum.all?(Map.keys(map), &is_binary/1) ->
        invalid("plugin patch keys must be strings")

      true ->
        key_bytes = map |> Map.keys() |> Enum.reduce(0, &(byte_size(&1) + &2))
        walk_all(Map.values(map), depth + 1, {nodes + 1, bytes + key_bytes})
    end
  end

  defp walk_size(list, depth, {nodes, bytes}) when is_list(list),
    do: walk_all(list, depth + 1, {nodes + 1, bytes})

  defp walk_size(bin, _depth, {nodes, bytes}) when is_binary(bin) do
    total = bytes + byte_size(bin)

    cond do
      byte_size(bin) > @max_string -> invalid("plugin patch string exceeds #{@max_string} bytes")
      total > @max_total_bytes -> invalid("plugin patch exceeds #{@max_total_bytes} string bytes")
      true -> {:ok, {nodes + 1, total}}
    end
  end

  defp walk_size(v, _depth, {nodes, bytes}) when is_number(v) or is_boolean(v) or is_nil(v),
    do: {:ok, {nodes + 1, bytes}}

  defp walk_size(v, _depth, _acc) when is_atom(v),
    do: invalid("plugin patch must not contain atoms (got #{inspect(v)})")

  defp walk_size(_v, _depth, _acc), do: invalid("plugin patch contains an unsupported term")

  defp walk_all(values, depth, acc) do
    Enum.reduce_while(values, {:ok, acc}, fn v, {:ok, acc} ->
      case walk_size(v, depth, acc) do
        {:ok, acc} -> {:cont, {:ok, acc}}
        err -> {:halt, err}
      end
    end)
  end

  # --- sections -------------------------------------------------------------

  defp apply_sections(report, patch, ctx) do
    patch
    |> Enum.sort_by(fn {section, _} -> section end)
    |> Enum.reduce_while({:ok, report, []}, fn {section, value}, {:ok, acc, written} ->
      case section(acc, section, value, ctx) do
        {:ok, next, new} -> {:cont, {:ok, next, written ++ new}}
        {:error, _} = err -> {:halt, err}
      end
    end)
  end

  defp section(_report, "embedded", _value, _ctx), do: invalid("embedded patches are not allowed")

  defp section(_report, name, _value, _ctx) when name in ["whiff", "integrity"],
    do: conflict("cannot patch protected section `#{name}`")

  defp section(_report, name, value, _ctx) when not is_map(value),
    do: invalid("patch section `#{name}` must be a map")

  defp section(report, "diagnostics", value, ctx), do: diagnostics(report, value, ctx)
  defp section(report, "security", value, ctx), do: security(report, value, ctx)
  defp section(report, "content", value, ctx), do: tree(report, ["content"], value, ctx)

  defp section(report, name, value, ctx) when name in @namespaced_sections,
    do: namespaced(report, name, value, ctx)

  defp section(report, name, value, ctx) when name in @tree_sections,
    do: tree(report, [name], value, ctx)

  defp section(_report, name, _value, _ctx), do: invalid("unsupported patch section `#{name}`")

  defp diagnostics(report, value, ctx) do
    case Map.keys(value) -- ["warnings"] do
      [] ->
        warnings = Map.get(value, "warnings", [])

        if is_list(warnings) and Enum.all?(warnings, &is_binary/1) do
          prefixed = Enum.map(warnings, &"elixir:#{ctx.id}: #{&1}")
          existing = report |> get(["diagnostics", "warnings"]) |> List.wrap()
          {:ok, put(report, ["diagnostics", "warnings"], existing ++ prefixed), []}
        else
          invalid("diagnostics.warnings must be a list of strings")
        end

      keys ->
        conflict("plugins may only add diagnostics.warnings (got #{inspect(keys)})")
    end
  end

  defp security(report, value, ctx) do
    case Map.keys(value) |> Enum.filter(&(&1 in ["secrets", "personal_data"])) do
      [] ->
        {risks, rest} = Map.pop(value, "risks")

        with {:ok, report, written} <- append_risks(report, risks, ctx),
             {:ok, report, more} <- security_fields(report, rest, ctx) do
          {:ok, report, written ++ more}
        end

      keys ->
        conflict("cannot patch native security fields: #{inspect(keys)}")
    end
  end

  defp append_risks(report, nil, _ctx), do: {:ok, report, []}

  defp append_risks(report, risks, ctx) when is_list(risks) do
    Enum.reduce_while(risks, {:ok, []}, fn risk, {:ok, acc} ->
      case validate_risk(risk) do
        :ok -> {:cont, {:ok, [Map.put(risk, "source", "elixir:#{ctx.id}") | acc]}}
        {:error, _} = err -> {:halt, err}
      end
    end)
    |> case do
      {:ok, []} ->
        {:ok, report, []}

      {:ok, new} ->
        existing = report |> get(["security", "risks"]) |> List.wrap()
        {:ok, put(report, ["security", "risks"], existing ++ Enum.reverse(new)), ["security.risks"]}

      err ->
        err
    end
  end

  defp append_risks(_report, _risks, _ctx), do: invalid("security.risks must be a list")

  defp validate_risk(%{} = risk) do
    cond do
      Map.keys(risk) -- @risk_keys != [] ->
        invalid("risk has unknown keys: #{inspect(Map.keys(risk) -- @risk_keys)}")

      not (is_binary(risk["kind"]) and risk["kind"] != "") ->
        invalid("risk.kind must be a non-empty string")

      risk["category"] not in @risk_categories ->
        invalid("risk.category must be one of #{inspect(@risk_categories)}")

      risk["severity"] not in @severities ->
        invalid("risk.severity must be one of #{inspect(@severities)}")

      not (is_nil(risk["detail"]) or is_binary(risk["detail"])) ->
        invalid("risk.detail must be a string")

      true ->
        :ok
    end
  end

  defp validate_risk(_), do: invalid("each security.risks entry must be a map")

  # Non-risk security keys may be added, never replaced (in any mode).
  defp security_fields(report, fields, _ctx) do
    Enum.reduce_while(Enum.sort(fields), {:ok, report, []}, fn {k, v}, {:ok, acc, written} ->
      path = ["security", k]

      cond do
        not has?(acc, path) -> {:cont, {:ok, put(acc, path, v), written ++ [join(path)]}}
        get(acc, path) == v -> {:cont, {:ok, acc, written}}
        true -> {:halt, conflict("cannot replace native `security.#{k}`")}
      end
    end)
  end

  defp namespaced(report, section, value, ctx) do
    Enum.reduce_while(Enum.sort(value), {:ok, report, []}, fn {k, v}, {:ok, acc, written} ->
      path = [section, k]
      dotted = join(path)

      cond do
        not has?(acc, path) ->
          {:cont, {:ok, put(acc, path, v), written ++ leaf_paths(v, dotted)}}

        get(acc, path) == v ->
          {:cont, {:ok, acc, written}}

        ctx.mode == :override and MapSet.member?(ctx.fields, dotted) ->
          {:cont, {:ok, put(acc, path, v), written ++ leaf_paths(v, dotted)}}

        true ->
          {:halt, conflict("namespace collision on `#{dotted}`")}
      end
    end)
  end

  defp tree(report, prefix, value, ctx) when is_map(value) do
    Enum.reduce_while(Enum.sort(value), {:ok, report, []}, fn {k, v}, {:ok, acc, written} ->
      case tree_key(acc, prefix ++ [k], v, ctx) do
        {:ok, next, new} -> {:cont, {:ok, next, written ++ new}}
        err -> {:halt, err}
      end
    end)
  end

  defp tree_key(report, ["content", "keywords"] = path, v, _ctx) when is_list(v) do
    existing = report |> get(path) |> List.wrap()
    merged = Enum.uniq(existing ++ v)

    if merged == existing,
      do: {:ok, report, []},
      else: {:ok, put(report, path, merged), ["content.keywords"]}
  end

  defp tree_key(report, path, v, ctx) do
    existing = get(report, path)

    cond do
      not has?(report, path) ->
        {:ok, put(report, path, v), leaf_paths(v, join(path))}

      is_map(existing) and is_map(v) ->
        tree(report, path, v, ctx)

      existing == v ->
        {:ok, report, []}

      true ->
        replace_leaf(report, path, v, ctx)
    end
  end

  defp replace_leaf(report, path, v, ctx) do
    dotted = join(path)
    declared? = ctx.mode == :override and MapSet.member?(ctx.fields, dotted)
    owned? = Enum.any?(ctx.owned, &(&1 == dotted or String.starts_with?(&1, dotted <> ".")))

    cond do
      declared? ->
        {:ok, put(report, path, v), leaf_paths(v, dotted)}

      owned? ->
        conflict("`#{dotted}` was already set by another plugin")

      ctx.mode == :override ->
        conflict("override of `#{dotted}` not declared in override_fields")

      ctx.mode == :fallback and hd(path) == "content" ->
        {:ok, put(report, path, v), leaf_paths(v, dotted)}

      true ->
        {:ok, report, []}
    end
  end

  # --- provenance -----------------------------------------------------------

  defp append_provenance(report, [], _id), do: report

  defp append_provenance(report, written, id) do
    existing = report |> get(["diagnostics", "provenance"])
    existing = if is_map(existing), do: existing, else: %{}
    new = Map.new(written, &{&1, "elixir:#{id}"})
    put(report, ["diagnostics", "provenance"], Map.merge(new, existing))
  end

  # --- helpers --------------------------------------------------------------

  defp leaf_paths(map, prefix) when is_map(map) and map_size(map) > 0 do
    Enum.flat_map(Enum.sort(map), fn {k, v} -> leaf_paths(v, "#{prefix}.#{k}") end)
  end

  defp leaf_paths(_value, prefix), do: [prefix]

  defp join(path), do: Enum.join(path, ".")

  defp has?(map, [key]) when is_map(map), do: Map.has_key?(map, key)
  defp has?(map, [key | rest]) when is_map(map), do: has?(Map.get(map, key), rest)
  defp has?(_, _), do: false

  defp get(map, [key]) when is_map(map), do: Map.get(map, key)
  defp get(map, [key | rest]) when is_map(map), do: get(Map.get(map, key), rest)
  defp get(_, _), do: nil

  defp put(map, [key], value), do: Map.put(map, key, value)

  defp put(map, [key | rest], value) do
    child = Map.get(map, key)
    Map.put(map, key, put(if(is_map(child), do: child, else: %{}), rest, value))
  end

  defp invalid(message), do: {:error, Whiff.Error.new(:invalid_report, message)}
  defp conflict(message), do: {:error, Whiff.Error.new(:conflict, message)}
end
