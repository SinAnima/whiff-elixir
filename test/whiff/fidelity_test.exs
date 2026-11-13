defmodule Whiff.FidelityTest do
  use ExUnit.Case, async: true

  @moduletag :native

  @fixtures Path.expand("../fixtures", __DIR__)
  @golden_dir Path.join(@fixtures, "golden")
  @goldens ~w(hello.txt tiny.jpg tiny.pdf sample.zip nested.zip corrupt.pdf empty.bin café.txt secret.secret pii.txt)

  defp fixture(name), do: Path.join(@fixtures, name)

  # Host- and checkout-dependent values: timings, filesystem metadata.
  @volatile_system ~w(device inode links allocated_bytes sparse hidden readonly)
  @volatile_security ~w(mode permissions owner setuid setgid sticky acl xattrs)

  defp normalize(report) when is_map(report) do
    report
    |> Map.new(fn
      {"source", v} -> {"source", Map.delete(v, "path")}
      {"temporal", v} -> {"temporal", Map.delete(v, "filesystem")}
      {"system", v} -> {"system", Map.drop(v, @volatile_system)}
      {"security", v} -> {"security", normalize(Map.drop(v, @volatile_security))}
      {"diagnostics", v} -> {"diagnostics", normalize(Map.drop(v, ["elapsed_ms"]))}
      {"ms", _} -> {"ms", 0}
      {k, v} -> {k, normalize(v)}
    end)
  end

  defp normalize(list) when is_list(list), do: Enum.map(list, &normalize/1)
  defp normalize(other), do: other

  defp schema do
    # Upstream schema is draft 2020-12; ex_json_schema supports draft 4/6/7.
    # The structural keywords used by the schema are the same.
    Path.expand("../../priv/schemas/whiff-1.schema.json", __DIR__)
    |> File.read!()
    |> Jason.decode!()
    |> Map.put("$schema", "http://json-schema.org/draft-07/schema#")
    |> ExJsonSchema.Schema.resolve()
  end

  defp assert_valid(report) do
    case ExJsonSchema.Validator.validate(schema(), report) do
      :ok -> :ok
      {:error, errors} -> flunk("schema errors: #{inspect(errors, limit: 5)}")
    end
  end

  describe "golden reports from pinned Rust whiff" do
    # Regenerate with:
    #   cargo build --release --manifest-path probes/rust_extract/Cargo.toml
    #   probes/rust_extract/target/release/whiff_rust_extract_probe --golden test/fixtures/<f> \
    #     > test/fixtures/golden/<f>.json
    for name <- @goldens do
      test name do
        golden =
          @golden_dir |> Path.join(unquote(name) <> ".json") |> File.read!() |> Jason.decode!()

        assert {:ok, report} = Whiff.extract(fixture(unquote(name)))
        assert normalize(report) == normalize(golden)
        assert_valid(report)
      end
    end
  end

  test "native text redaction applies under both privacy modes" do
    # Upstream redacts secrets and the text excerpt in both modes; `:off`
    # changes how personal data in structured fields is reported.
    for privacy <- [:strict, :off] do
      {:ok, report} = Whiff.extract(fixture("pii.txt"), hashes: :none, privacy: privacy)
      assert report["content"]["excerpt"] =~ "[redacted:email]"
      refute report["content"]["excerpt"] =~ "jane.doe@example.com"
    end
  end

  test "plugin-merged reports validate against the schema" do
    {:ok, report} =
      Whiff.extract(fixture("sample.trade"),
        extractors: [Whiff.Test.TradeWhiffer],
        analyzers: [Whiff.Test.TitleAnalyzer, Whiff.Test.RiskAnalyzer],
        provenance: true,
        hashes: :none
      )

    assert_valid(report)
  end

  test "binary input uses the supplied name" do
    bytes = File.read!(fixture("tiny.jpg"))
    assert {:ok, report} = Whiff.extract_binary(bytes, name: "photo.jpg", hashes: :none)
    assert report["source"]["name"] == "photo.jpg"
    assert report["identification"]["format"] == "jpeg"
    assert report["system"]["kind"] == "memory"
  end

  test "binary input without a name is detected by content" do
    assert {:ok, report} = Whiff.extract_binary(File.read!(fixture("tiny.pdf")), hashes: :none)
    assert report["identification"]["format"] == "pdf"
    refute Map.has_key?(report["source"], "name")
  end

  test "a directory is reported, not an error" do
    assert {:ok, report} = Whiff.extract(@fixtures, hashes: :none)
    assert report["system"]["kind"] == "directory"
  end

  test "a relative path is kept as given" do
    assert {:ok, report} = Whiff.extract("test/fixtures/hello.txt", hashes: :none)
    assert report["source"]["path"] == "test/fixtures/hello.txt"
  end

  test "a Unicode file name" do
    assert {:ok, report} = Whiff.extract(fixture("café.txt"), hashes: :none)
    assert report["source"]["name"] == "café.txt"
  end

  test "a non-UTF-8 path returns an error tuple, never raises" do
    path = fixture(<<"missing-", 0xFF, ".txt">>)

    assert {:error, %Whiff.Error{reason: reason}} = Whiff.extract(path)
    assert reason in [:enoent, :unsupported_input]

    assert {:error, %Whiff.Error{}} = Whiff.llm(path)
  end

  test "a non-UTF-8 name for binary input is accepted" do
    assert {:ok, report} = Whiff.extract_binary("hi\n", name: <<"n", 0xFF, ".txt">>, hashes: :none)
    assert is_binary(report["source"]["name"])
  end

  test "empty and NUL-containing paths are :unsupported_input" do
    assert {:error, %Whiff.Error{reason: :unsupported_input}} = Whiff.extract("")
    assert {:error, %Whiff.Error{reason: :unsupported_input}} = Whiff.extract("a\0b")
  end

  @tag :unix
  test "a symlink is followed" do
    link = Path.join(System.tmp_dir!(), "whiff-link-#{System.unique_integer([:positive])}.txt")
    File.ln_s!(fixture("hello.txt"), link)

    try do
      assert {:ok, report} = Whiff.extract(link, hashes: :none)
      assert report["identification"]["format"] == "text"
    after
      File.rm!(link)
    end
  end

  test "native limits truncate work and the call still succeeds" do
    assert {:ok, report} =
             Whiff.extract(fixture("nested.zip"), limits: [max_depth: 0], hashes: :none)

    assert report["embedded"] in [nil, []] or
             Enum.all?(report["embedded"], &(&1["embedded"] in [nil, []]))

    assert {:ok, report} = Whiff.extract(fixture("hello.txt"), limits: [max_read_bytes: 4])
    assert is_list(report["diagnostics"]["limits_hit"])
    assert report["diagnostics"]["limits_hit"] != []
  end

  test "skip removes a native extractor run" do
    assert {:ok, report} =
             Whiff.extract(fixture("hello.txt"), skip: ["text.keywords"], hashes: :none)

    refute "text.keywords" in Whiff.Report.extractor_ids(report)
  end

  test "format forces the format id" do
    assert {:ok, report} = Whiff.extract(fixture("hello.txt"), format: "json", hashes: :none)
    assert report["identification"]["format"] == "json"
  end
end
