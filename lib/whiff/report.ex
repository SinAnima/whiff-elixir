defmodule Whiff.Report do
  @moduledoc """
  Helpers for decoding and inspecting `whiff/1` reports (string-keyed maps).

  Reports from the NIF arrive as UTF-8 JSON and are decoded with Jason into
  maps whose keys are binaries (never uncontrolled atoms).
  """

  @schema "whiff/1"

  @top_level ~w(
    whiff source identification system temporal security rights physical
    integrity content metadata format embedded diagnostics
  )

  @doc """
  Schema identifier written to `whiff.schema` (`"whiff/1"`).

  ## Examples

      iex> Whiff.Report.schema_version()
      "whiff/1"
  """
  @spec schema_version() :: String.t()
  def schema_version, do: @schema

  @doc """
  Stable top-level section names for a `whiff/1` report.

  ## Examples

      iex> "identification" in Whiff.Report.top_level_sections()
      true
  """
  @spec top_level_sections() :: [String.t()]
  def top_level_sections, do: @top_level

  @doc """
  Decode JSON bytes from the NIF into a string-keyed map.

  ## Arguments

  * `json` — UTF-8 JSON binary

  ## Returns

  * `{:ok, map}` — JSON object
  * `{:error, %Whiff.Error{reason: :invalid_report}}` — non-object root or decode failure

  ## Examples

      iex> Whiff.Report.decode(~s({"whiff":{"schema":"whiff/1"}}))
      {:ok, %{"whiff" => %{"schema" => "whiff/1"}}}

      iex> Whiff.Report.decode("[1]")
      {:error, %Whiff.Error{reason: :invalid_report, message: "report JSON root must be an object", path: nil, details: %{}}}

      iex> match?({:error, %Whiff.Error{reason: :invalid_report}}, Whiff.Report.decode("not-json"))
      true
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
  Whether native extraction appears to have covered the identified format.

  Used by the registry to decide `:fallback` extractors. Low-confidence
  heuristic text hits without `extension_matches` are not treated as covered,
  so proprietary extensions that look like plain text still get Elixir Whiffers.

  ## Arguments

  * `report` — string-keyed report map

  ## Returns

  `true` when a covering extractor ran successfully (or partially); otherwise `false`.

  ## Examples

      iex> Whiff.Report.native_covered?(%{})
      false

      iex> report = %{
      ...>   "identification" => %{
      ...>     "extractor" => "text.plain",
      ...>     "extension_matches" => true,
      ...>     "detected_by" => "extension"
      ...>   },
      ...>   "diagnostics" => %{"extractors" => [%{"id" => "text.plain", "status" => "ok"}]}
      ...> }
      iex> Whiff.Report.native_covered?(report)
      true
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
  Append an extractor/analyzer diagnostic entry under `diagnostics.extractors`.

  ## Arguments

  * `report` — string-keyed report map
  * `entry` — diagnostic map (typically `"id"`, `"status"`, optional `"message"`)

  ## Returns

  Updated report map.

  ## Examples

      iex> Whiff.Report.append_extractor_diag(%{}, %{"id" => "myapp.trade", "status" => "ok"})
      %{"diagnostics" => %{"extractors" => [%{"id" => "myapp.trade", "status" => "ok"}]}}
  """
  @spec append_extractor_diag(map(), map()) :: map()
  def append_extractor_diag(report, entry) when is_map(report) and is_map(entry) do
    diagnostics = Map.get(report, "diagnostics") || %{}
    extractors = List.wrap(Map.get(diagnostics, "extractors"))
    diagnostics = Map.put(diagnostics, "extractors", extractors ++ [entry])
    Map.put(report, "diagnostics", diagnostics)
  end
end
