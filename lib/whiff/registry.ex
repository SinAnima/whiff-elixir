defmodule Whiff.Registry do
  @moduledoc false

  # Runs Elixir extractors, then analyzers, against a native report.
  #
  # Order is the list order from the call (or app config). Every run, success
  # or failure, is recorded in `diagnostics.extractors` in the schema
  # `ExtractorRun` shape. With `strict: true` the first failure is returned
  # as `{:error, %Whiff.Error{}}` instead.

  alias Whiff.{Error, Input, Merge, Options, Plugin, Privacy, Report}

  @max_id_bytes 128
  @max_version 4_294_967_295
  @max_error_bytes 256
  @meta_timeout_ms 1_000

  @doc "Run the plugin pipeline. `opts` is the normalized options map."
  @spec run(Input.t(), map(), map()) :: {:ok, map()} | {:error, Error.t()}
  def run(%Input{} = input, report, opts) when is_map(report) and is_map(opts) do
    ctx = %{
      mode: Map.get(opts, :mode, :fallback),
      strict?: Map.get(opts, :strict, false),
      timeout: Map.get(opts, :plugin_timeout_ms, 5_000),
      privacy: Map.get(opts, :privacy, :strict),
      provenance?: Map.get(opts, :provenance, false),
      override_fields: Map.get(opts, :override_fields, []),
      native_ids: MapSet.new(Report.extractor_ids(report)),
      covered?: Report.native_covered?(report),
      unreadable?: Report.unreadable?(report)
    }

    with {:ok, extractors} <- resolve(opts, :extractors),
         {:ok, analyzers} <- resolve(opts, :analyzers),
         {:ok, report, owned} <- run_extractors(input, report, extractors, ctx),
         {:ok, report, _owned} <- run_analyzers(input, report, owned, analyzers, ctx) do
      {:ok, report}
    end
  end

  # Per-call lists were validated by Options; app config is validated here.
  defp resolve(opts, kind) do
    case Map.fetch(opts, kind) do
      {:ok, list} -> {:ok, list}
      :error -> Options.validate_modules(Application.get_env(:whiff, kind, []), kind)
    end
  end

  defp run_extractors(input, report, extractors, ctx) do
    reduce_plugins(extractors, report, MapSet.new(), fn mod, acc, owned ->
      run_extractor(mod, input, acc, owned, ctx)
    end)
  end

  defp run_analyzers(input, report, owned, analyzers, ctx) do
    reduce_plugins(analyzers, report, owned, fn mod, acc, owned ->
      run_analyzer(mod, input, acc, owned, ctx)
    end)
  end

  # Analyzer patches always merge in :augment mode.
  defp run_analyzer(mod, input, report, owned, ctx) do
    case metadata(mod, :analyzer, ctx) do
      {:ok, meta} ->
        meta
        |> timed(fn -> mod.analyze(report, input) end, ctx)
        |> outcome(report, owned, :augment, ctx)

      {:error, err, meta} ->
        failure(report, owned, err, meta, ctx)
    end
  end

  defp reduce_plugins(mods, report, owned, fun) do
    Enum.reduce_while(mods, {:ok, report, owned}, fn mod, {:ok, acc, owned} ->
      case fun.(mod, acc, owned) do
        {:ok, next, owned} -> {:cont, {:ok, next, owned}}
        {:error, _} = err -> {:halt, err}
      end
    end)
  end

  defp run_extractor(mod, input, report, owned, ctx) do
    with {:ok, meta} <- metadata(mod, :extractor, ctx),
         {:ok, true} <- supports(mod, input, report, meta, ctx) do
      extract(mod, meta, input, report, owned, ctx)
    else
      {:ok, _not_supported} -> {:ok, report, owned}
      {:error, err, meta} -> failure(report, owned, err, meta, ctx)
    end
  end

  # :fallback never runs when native covered the file or could not read it.
  defp extract(_mod, _meta, _input, report, owned, %{mode: :fallback} = ctx)
       when ctx.covered? or ctx.unreadable?,
       do: {:ok, report, owned}

  defp extract(mod, meta, input, report, owned, ctx) do
    meta
    |> timed(fn -> mod.extract(input, report) end, ctx)
    |> outcome(report, owned, ctx.mode, ctx)
  end

  defp supports(mod, input, report, meta, ctx) do
    case Plugin.run(fn -> mod.supports?(input, report) end,
           timeout: ctx.timeout,
           id: meta.id,
           kind: meta.kind
         ) do
      {:ok, value} -> {:ok, value === true}
      {:error, err} -> {:error, err, meta}
    end
  end

  # id/0 and version/0 run isolated too, so a hanging or raising callback
  # cannot block or crash the caller.
  defp metadata(mod, kind, ctx) do
    fallback = %{id: inspect(mod), version: 0, kind: kind, ms: 0.0}

    case Plugin.run(fn -> {mod.id(), mod.version()} end,
           timeout: min(ctx.timeout, @meta_timeout_ms),
           id: fallback.id,
           kind: kind
         ) do
      {:ok, {id, version}} ->
        validate_metadata(id, version, fallback, ctx)

      {:ok, _other} ->
        {:error, Error.new(reason_for(kind), "id/0 or version/0 failed"), fallback}

      {:error, err} ->
        {:error, err, fallback}
    end
  end

  defp validate_metadata(id, version, fallback, ctx) do
    error = fn reason, message -> {:error, Error.new(reason, message), fallback} end

    cond do
      not valid_id?(id) ->
        error.(
          reason_for(fallback.kind),
          "id/0 must return a non-empty string (max #{@max_id_bytes} bytes)"
        )

      not valid_version?(version) ->
        error.(reason_for(fallback.kind), "version/0 must return an integer in 0..#{@max_version}")

      MapSet.member?(ctx.native_ids, id) ->
        error.(:conflict, "plugin id `#{id}` collides with a native extractor id")

      true ->
        {:ok, %{fallback | id: id, version: version}}
    end
  end

  defp valid_id?(id),
    do: is_binary(id) and id != "" and byte_size(id) <= @max_id_bytes and String.valid?(id)

  defp valid_version?(v), do: is_integer(v) and v >= 0 and v <= @max_version

  defp timed(meta, fun, ctx) do
    t0 = System.monotonic_time(:microsecond)
    result = Plugin.run(fun, timeout: ctx.timeout, id: meta.id, kind: meta.kind)
    {result, %{meta | ms: (System.monotonic_time(:microsecond) - t0) / 1000}}
  end

  defp outcome({result, meta}, report, owned, mode, ctx) do
    case result do
      {:ok, {:ok, patch}} when is_map(patch) ->
        apply_patch(report, owned, patch, mode, meta, ctx)

      {:ok, {:error, %Error{} = err}} ->
        failure(report, owned, err, meta, ctx)

      {:ok, other} ->
        err =
          Error.new(
            reason_for(meta.kind),
            "#{meta.kind} returned #{shape(other)}; expected {:ok, map} or {:error, %Whiff.Error{}}"
          )

        failure(report, owned, err, meta, ctx)

      {:error, %Error{} = err} ->
        failure(report, owned, err, meta, ctx)
    end
  end

  defp apply_patch(report, owned, patch, mode, meta, ctx) do
    with :ok <- Merge.validate_patch(patch),
         {:ok, patch} <- Privacy.scrub_patch(patch, ctx.privacy),
         {:ok, merged, written} <-
           Merge.merge_tracked(report, patch,
             mode: mode,
             override_fields: ctx.override_fields,
             plugin_id: meta.id,
             provenance: ctx.provenance?,
             owned: owned
           ) do
      entry = %{"id" => meta.id, "version" => meta.version, "ms" => meta.ms, "status" => "ok"}
      {:ok, Report.append_extractor_diag(merged, entry), MapSet.union(owned, MapSet.new(written))}
    else
      {:error, %Error{} = err} -> failure(report, owned, err, meta, ctx)
    end
  end

  defp failure(_report, _owned, %Error{} = err, meta, %{strict?: true} = ctx) do
    {:error, %{sanitize(err, ctx) | details: Map.put(err.details, :plugin, meta.id)}}
  end

  defp failure(report, owned, %Error{} = err, meta, ctx) do
    err = sanitize(err, ctx)

    entry = %{
      "id" => meta.id,
      "version" => meta.version,
      "ms" => meta.ms,
      "status" => "error",
      "error_kind" => Atom.to_string(err.reason),
      "error" => err.message
    }

    {:ok, Report.append_extractor_diag(report, entry), owned}
  end

  # Plugin-authored messages may carry extracted content.
  defp sanitize(%Error{message: message} = err, ctx) do
    message = if is_binary(message), do: message, else: ""
    message = message |> Privacy.scrub_string(ctx.privacy) |> truncate()
    %{err | message: message}
  end

  defp truncate(message) when byte_size(message) <= @max_error_bytes, do: message

  defp truncate(message) do
    cut = binary_part(message, 0, @max_error_bytes)
    if String.valid?(cut), do: cut <> "...", else: String.slice(message, 0, 200) <> "..."
  end

  defp shape(value) when is_tuple(value), do: "a tuple of size #{tuple_size(value)}"
  defp shape(value) when is_map(value), do: "a map"
  defp shape(value) when is_list(value), do: "a list"
  defp shape(value) when is_binary(value), do: "a binary"
  defp shape(value) when is_atom(value), do: "an atom"
  defp shape(_value), do: "an unsupported term"

  defp reason_for(:analyzer), do: :analyzer_error
  defp reason_for(_), do: :extractor_error
end
