defmodule Whiff.Report do
  @moduledoc """
  Helpers for decoding and inspecting `whiff/1` reports (string-keyed maps).
  """

  @schema "whiff/1"

  @top_level ~w(
    whiff source identification system temporal security rights physical
    integrity content metadata format embedded diagnostics
  )

  @doc "The schema identifier written to `whiff.schema`."
  @spec schema_version() :: String.t()
  def schema_version, do: @schema

  @doc "Stable top-level section names."
  @spec top_level_sections() :: [String.t()]
  def top_level_sections, do: @top_level

  @doc """
  Decode JSON bytes from the NIF into a string-keyed map.
  """
  @spec decode(binary()) :: {:ok, map()} | {:error, Whiff.Error.t()}
  def decode(json) when is_binary(json) do
    case Jason.decode(json) do
      {:ok, map} when is_map(map) ->
        {:ok, map}

      {:ok, _} ->
        {:error, Whiff.Error.new(:invalid_report, "report JSON root must be an object")}

      {:error, err} ->
        {:error,
         Whiff.Error.new(:invalid_report, "failed to decode report JSON: #{Exception.message(err)}")}
    end
  end

  @doc """
  True when native extraction appears to have run a covering extractor for the
  identified format (not mere magic detection).

  Low-confidence heuristic text hits without `extension_matches` are **not**
  treated as covered — proprietary extensions often look like plain text to
  upstream, and Elixir `:fallback` Whiffers must still run for those.
  """
  @spec native_covered?(map()) :: boolean()
  def native_covered?(report) when is_map(report) do
    id = report["identification"] || %{}
    extractor = id["extractor"]

    covered_extractor?(extractor) and
      id["extension_matches"] != false and
      not heuristic_without_extension?(id) and
      extractor_diag_ok?(report, extractor)
  end

  defp covered_extractor?(extractor), do: is_binary(extractor) and extractor != ""

  defp heuristic_without_extension?(id) do
    id["detected_by"] == "heuristic" and id["extension_matches"] != true
  end

  defp extractor_diag_ok?(report, extractor) do
    extractors = get_in(report, ["diagnostics", "extractors"]) || []

    Enum.any?(extractors, fn run ->
      is_map(run) and run["id"] == extractor and run["status"] in ["ok", "partial"]
    end)
  end

  @doc """
  Append an extractor/analyzer diagnostic entry.
  """
  @spec append_extractor_diag(map(), map()) :: map()
  def append_extractor_diag(report, entry) when is_map(report) and is_map(entry) do
    diagnostics = Map.get(report, "diagnostics") || %{}
    extractors = List.wrap(Map.get(diagnostics, "extractors"))
    diagnostics = Map.put(diagnostics, "extractors", extractors ++ [entry])
    Map.put(report, "diagnostics", diagnostics)
  end
end
