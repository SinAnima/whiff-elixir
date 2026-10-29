defmodule Whiff.Registry do
  @moduledoc false

  alias Whiff.{Input, Merge, Plugin, Privacy, Report}

  @type ctx :: %{
          mode: atom(),
          strict?: boolean(),
          timeout: pos_integer(),
          privacy: atom(),
          provenance?: boolean(),
          override_fields: [String.t()]
        }

  @doc """
  Run the Elixir extractor/analyzer pipeline against a native report.
  """
  @spec run(Input.t(), map(), map()) :: {:ok, map()} | {:error, Whiff.Error.t()}
  def run(%Input{} = input, report, opts) when is_map(report) and is_map(opts) do
    ctx = %{
      mode: Map.get(opts, :mode, :fallback),
      strict?: Map.get(opts, :strict, false),
      timeout: Map.get(opts, :plugin_timeout_ms, 5_000),
      privacy: Map.get(opts, :privacy, :strict),
      provenance?: Map.get(opts, :provenance, false),
      override_fields: Map.get(opts, :override_fields, [])
    }

    extractors = resolve_extractors(opts)
    analyzers = resolve_analyzers(opts)

    with {:ok, report} <- run_extractors(input, report, extractors, ctx),
         {:ok, report} <- run_analyzers(input, report, analyzers, ctx) do
      {:ok, report}
    end
  end

  defp resolve_extractors(opts) do
    call = Map.get(opts, :extractors)
    config = Application.get_env(:whiff, :extractors, [])
    List.wrap(call || config)
  end

  defp resolve_analyzers(opts) do
    call = Map.get(opts, :analyzers)
    config = Application.get_env(:whiff, :analyzers, [])
    List.wrap(call || config)
  end

  defp run_extractors(input, report, extractors, ctx) do
    covered? = Report.native_covered?(report)

    Enum.reduce_while(extractors, {:ok, report}, fn mod, {:ok, acc} ->
      case maybe_run_extractor(mod, input, acc, covered?, ctx) do
        {:ok, next} -> {:cont, {:ok, next}}
        {:error, _} = err -> {:halt, err}
        :skip -> {:cont, {:ok, acc}}
      end
    end)
  end

  defp maybe_run_extractor(mod, input, report, covered?, ctx) do
    id = safe_id(mod)

    case Plugin.run(fn -> mod.supports?(input, report) end,
           timeout: ctx.timeout,
           id: id,
           kind: :extractor
         ) do
      {:error, err} ->
        if ctx.strict?, do: {:error, err}, else: :skip

      {:ok, true} ->
        if ctx.mode == :fallback and covered? do
          :skip
        else
          do_extract(mod, input, report, id, ctx)
        end

      {:ok, _} ->
        :skip
    end
  end

  defp do_extract(mod, input, report, id, ctx) do
    t0 = System.monotonic_time(:microsecond)

    result =
      Plugin.run(fn -> mod.extract(input, report) end,
        timeout: ctx.timeout,
        id: id,
        kind: :extractor
      )

    ms = (System.monotonic_time(:microsecond) - t0) / 1000
    version = safe_version(mod)
    meta = %{id: id, version: version, ms: ms}

    case result do
      {:ok, {:ok, patch}} when is_map(patch) ->
        finish_patch(report, patch, ctx.mode, meta, ctx)

      {:ok, {:error, %Whiff.Error{} = err}} ->
        handle_plugin_failure(report, err, meta, ctx.strict?)

      {:ok, other} ->
        err =
          Whiff.Error.new(
            :extractor_error,
            "extractor returned unexpected value: #{inspect(other)}",
            details: %{plugin: id}
          )

        handle_plugin_failure(report, err, meta, ctx.strict?)

      {:error, %Whiff.Error{} = err} ->
        handle_plugin_failure(report, err, meta, ctx.strict?)
    end
  end

  defp run_analyzers(input, report, analyzers, ctx) do
    Enum.reduce_while(analyzers, {:ok, report}, fn mod, {:ok, acc} ->
      id = safe_id(mod)
      version = safe_version(mod)
      t0 = System.monotonic_time(:microsecond)

      result =
        Plugin.run(fn -> mod.analyze(acc, input) end,
          timeout: ctx.timeout,
          id: id,
          kind: :analyzer
        )

      ms = (System.monotonic_time(:microsecond) - t0) / 1000
      meta = %{id: id, version: version, ms: ms}
      outcome = analyzer_outcome(acc, result, meta, ctx)

      case outcome do
        {:ok, next} -> {:cont, {:ok, next}}
        {:error, _} = e -> {:halt, e}
      end
    end)
  end

  defp analyzer_outcome(report, result, meta, ctx) do
    case result do
      {:ok, {:ok, patch}} when is_map(patch) ->
        finish_patch(report, patch, :augment, meta, ctx)

      {:ok, {:error, %Whiff.Error{} = err}} ->
        handle_plugin_failure(report, err, meta, ctx.strict?)

      {:ok, other} ->
        err =
          Whiff.Error.new(
            :analyzer_error,
            "analyzer returned unexpected value: #{inspect(other)}",
            details: %{plugin: meta.id}
          )

        handle_plugin_failure(report, err, meta, ctx.strict?)

      {:error, %Whiff.Error{} = err} ->
        handle_plugin_failure(report, err, meta, ctx.strict?)
    end
  end

  defp finish_patch(report, patch, mode, meta, ctx) do
    with {:ok, patch} <- Privacy.scrub_patch(patch, ctx.privacy),
         {:ok, merged} <-
           Merge.merge(report, patch,
             mode: mode,
             override_fields: ctx.override_fields,
             plugin_id: meta.id,
             provenance: ctx.provenance?
           ) do
      entry = %{
        "id" => meta.id,
        "version" => meta.version,
        "ms" => meta.ms,
        "status" => "ok"
      }

      {:ok, Report.append_extractor_diag(merged, entry)}
    else
      {:error, %Whiff.Error{} = err} ->
        handle_plugin_failure(report, err, meta, ctx.strict?)
    end
  end

  defp handle_plugin_failure(_report, err, _meta, true), do: {:error, err}

  defp handle_plugin_failure(report, err, meta, false) do
    entry = %{
      "id" => meta.id,
      "version" => meta.version,
      "ms" => meta.ms,
      "status" => "error",
      "error_kind" => to_string(err.reason),
      "error" => err.message
    }

    {:ok, Report.append_extractor_diag(report, entry)}
  end

  defp safe_id(mod) do
    Code.ensure_loaded(mod)

    if function_exported?(mod, :id, 0), do: mod.id(), else: inspect(mod)
  rescue
    _ -> inspect(mod)
  end

  defp safe_version(mod) do
    Code.ensure_loaded(mod)

    if function_exported?(mod, :version, 0), do: mod.version(), else: 1
  rescue
    _ -> 1
  end
end
