defmodule Whiff.ReportTest do
  use ExUnit.Case, async: true

  doctest Whiff.Report

  alias Whiff.Report

  test "schema helpers" do
    assert Report.schema_version() == "whiff/1"
    assert "identification" in Report.top_level_sections()
  end

  test "decode accepts objects and rejects other JSON roots" do
    assert {:ok, %{"a" => 1}} = Report.decode(~s({"a":1}))
    assert {:error, %Whiff.Error{reason: :invalid_report}} = Report.decode(~s([1,2]))
    assert {:error, %Whiff.Error{reason: :invalid_report}} = Report.decode("not-json")
  end

  test "native_covered? requires extractor and matching diagnostics" do
    refute Report.native_covered?(%{})

    refute Report.native_covered?(%{
             "identification" => %{"extractor" => "text.plain", "extension_matches" => true}
           })

    report = %{
      "identification" => %{
        "extractor" => "text.plain",
        "extension_matches" => true,
        "detected_by" => "extension"
      },
      "diagnostics" => %{"extractors" => [%{"id" => "text.plain", "status" => "ok"}]}
    }

    assert Report.native_covered?(report)

    heuristic = %{
      "identification" => %{
        "extractor" => "text.plain",
        "detected_by" => "heuristic",
        "extension_matches" => false
      },
      "diagnostics" => %{"extractors" => [%{"id" => "text.plain", "status" => "ok"}]}
    }

    refute Report.native_covered?(heuristic)
  end

  test "append_extractor_diag creates diagnostics when missing" do
    report = Report.append_extractor_diag(%{}, %{"id" => "x", "status" => "ok"})
    assert get_in(report, ["diagnostics", "extractors"]) == [%{"id" => "x", "status" => "ok"}]
  end
end
