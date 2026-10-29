defmodule Whiff.PluginTest do
  use ExUnit.Case, async: false

  @moduletag :plugin

  @trade Path.expand("../fixtures/sample.trade", __DIR__)
  @hello Path.expand("../fixtures/hello.txt", __DIR__)
  @secret Path.expand("../fixtures/secret.secret", __DIR__)
  @slow Path.expand("../fixtures/hang.slow", __DIR__)

  test "fallback whiffer for proprietary .trade" do
    assert {:ok, report} =
             Whiff.extract(@trade,
               extractors: [Whiff.Test.TradeWhiffer],
               mode: :fallback,
               hashes: :none
             )

    assert get_in(report, ["format", "test.trade", "trade_id"]) == "T-1001"
    assert get_in(report, ["content", "title"]) =~ "Trade"
  end

  test "fallback whiffer accepts CRLF trade fixtures (Windows checkouts)" do
    path = Path.join(System.tmp_dir!(), "whiff-crlf-#{System.unique_integer([:positive])}.trade")

    File.write!(
      path,
      "TRADE/1\r\nid=T-1001\r\ncurrency=USD\r\nqty=10\r\nprice=42.5\r\n"
    )

    try do
      assert {:ok, report} =
               Whiff.extract(path,
                 extractors: [Whiff.Test.TradeWhiffer],
                 mode: :fallback,
                 hashes: :none
               )

      assert get_in(report, ["format", "test.trade", "trade_id"]) == "T-1001"
    after
      File.rm(path)
    end
  end

  test "augment known text with extra format namespace" do
    assert {:ok, report} =
             Whiff.extract(@hello,
               extractors: [Whiff.Test.AugmentPdfWhiffer],
               mode: :augment,
               hashes: :none
             )

    assert get_in(report, ["format", "test.pdf_augment", "reviewed"]) == true
    assert "augmented" in List.wrap(get_in(report, ["content", "keywords"]))
  end

  test "override declared field" do
    assert {:ok, report} =
             Whiff.extract(@hello,
               extractors: [Whiff.Test.AugmentPdfWhiffer],
               mode: :override,
               override_fields: ["content.title"],
               hashes: :none
             )

    assert is_map(report)
  end

  test "analyzer runs after extractors" do
    assert {:ok, report} =
             Whiff.extract(@trade,
               extractors: [Whiff.Test.TradeWhiffer],
               analyzers: [Whiff.Test.TitleAnalyzer],
               mode: :fallback,
               hashes: :none
             )

    assert get_in(report, ["metadata", "test.title_analyzer", "normalized_title"]) =~ "TRADE"
  end

  test "raising analyzer adds diagnostics by default" do
    assert {:ok, report} =
             Whiff.extract(@hello,
               analyzers: [Whiff.Test.RaisingAnalyzer],
               hashes: :none
             )

    extractors = get_in(report, ["diagnostics", "extractors"]) || []
    assert Enum.any?(extractors, &(&1["id"] == "test.raising_analyzer" and &1["status"] == "error"))
  end

  test "strict mode turns analyzer failure into error" do
    assert {:error, %Whiff.Error{}} =
             Whiff.extract(@hello,
               analyzers: [Whiff.Test.RaisingAnalyzer],
               strict: true,
               hashes: :none
             )
  end

  test "plugin timeout" do
    assert {:ok, report} =
             Whiff.extract(@slow,
               extractors: [Whiff.Test.SlowExtractor],
               mode: :fallback,
               plugin_timeout_ms: 50,
               hashes: :none
             )

    extractors = get_in(report, ["diagnostics", "extractors"]) || []
    assert Enum.any?(extractors, &(&1["id"] == "test.slow" and &1["status"] == "error"))
  end

  @tag :privacy
  test "strict privacy redacts secrets from plugin patch" do
    assert {:ok, report} =
             Whiff.extract(@secret,
               extractors: [Whiff.Test.SecretWhiffer],
               mode: :fallback,
               privacy: :strict,
               hashes: :none
             )

    excerpt = get_in(report, ["content", "excerpt"]) || ""
    refute excerpt =~ "agent@example.com"
    refute excerpt =~ "hunter2"
    assert excerpt =~ "REDACTED"
  end

  test "fallback does not run when native covers format" do
    assert {:ok, report} =
             Whiff.extract(@hello,
               extractors: [Whiff.Test.AugmentPdfWhiffer],
               mode: :fallback,
               hashes: :none
             )

    # Augment whiffer supports .txt but fallback should skip when covered
    refute get_in(report, ["format", "test.pdf_augment"])
  end

  test "extract_many collects results" do
    assert {:ok, pairs} =
             Whiff.extract_many([@hello, @trade],
               max_concurrency: 2,
               extractors: [Whiff.Test.TradeWhiffer],
               hashes: :none
             )

    assert length(pairs) == 2

    assert Enum.all?(pairs, fn {_path, result} ->
             match?({:ok, _}, result) or match?({:error, _}, result)
           end)
  end

  test "Input.present never includes bytes" do
    input = Whiff.Input.from_binary(:binary.copy(<<0>>, 1000), name: "x.bin")
    present = Whiff.Input.present(input)
    refute Map.has_key?(present, :bytes)
    assert present.size == 1000
  end

  test "merge rejects embedded patches" do
    report = %{"whiff" => %{"schema" => "whiff/1"}, "embedded" => []}

    assert {:error, %Whiff.Error{reason: :invalid_report}} =
             Whiff.Merge.merge(report, %{"embedded" => [%{}]}, mode: :augment)
  end

  test "merge rejects atom keys in patch" do
    report = %{"whiff" => %{"schema" => "whiff/1"}}

    assert {:error, %Whiff.Error{reason: :invalid_report}} =
             Whiff.Merge.merge(report, %{content: %{"title" => "x"}}, mode: :augment)
  end
end
