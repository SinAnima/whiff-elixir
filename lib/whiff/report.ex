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

  The pipeline uses this to decide whether `:fallback` extractors run. Native
  coverage requires all of:

  * `identification.extractor` is a non-empty string
  * `identification.extension_matches` is not `false`
  * the format was not detected by `"heuristic"` without a matching extension
  * `diagnostics.extractors` has an entry for that extractor with status `"ok"`

  A proprietary `.trade` file that only looks like plain text is therefore not
  covered, and an Elixir extractor can handle it.

  ## Arguments

  * `report` — string-keyed report map

  ## Returns

  `true` when native extraction covered the file, otherwise `false`.

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

      iex> Whiff.Report.native_covered?(%{
      ...>   "identification" => %{"extractor" => "text.plain", "detected_by" => "heuristic"},
      ...>   "diagnostics" => %{"extractors" => [%{"id" => "text.plain", "status" => "ok"}]}
      ...> })
      false
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
      is_map(run) and run["id"] == extractor and run["status"] == "ok"
    end)
  end

  @doc """
  Whether native extraction could not read the file.

  Upstream returns a report (not an error) for a file that exists but cannot
  be opened, with `identification.format == "unreadable"` and a
  `diagnostics.warnings` entry such as `"cannot open: Permission denied"`.
  `:fallback` extractors do not run for such reports.

  ## Examples

      iex> Whiff.Report.unreadable?(%{"identification" => %{"format" => "unreadable"}})
      true

      iex> Whiff.Report.unreadable?(%{"identification" => %{"format" => "text"}})
      false
  """
  @spec unreadable?(map()) :: boolean()
  def unreadable?(report) when is_map(report),
    do: get_in(report, ["identification", "format"]) == "unreadable"

  @doc """
  Ids of all runs listed in `diagnostics.extractors`.

  ## Examples

      iex> Whiff.Report.extractor_ids(%{"diagnostics" => %{"extractors" => [%{"id" => "text.plain"}, %{"id" => "meta.mwg"}]}})
      ["text.plain", "meta.mwg"]

      iex> Whiff.Report.extractor_ids(%{})
      []
  """
  @spec extractor_ids(map()) :: [String.t()]
  def extractor_ids(report) when is_map(report) do
    for %{"id" => id} <- List.wrap(get_in(report, ["diagnostics", "extractors"])), do: id
  end

  @doc """
  Append an extractor/analyzer diagnostic entry under `diagnostics.extractors`.

  ## Arguments

  * `report` — string-keyed report map
  * `entry` — map in the schema `ExtractorRun` shape: `"id"`, `"version"`,
    `"ms"`, `"status"` (`"ok"` | `"error"`), and optionally `"error_kind"`
    and `"error"`

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
