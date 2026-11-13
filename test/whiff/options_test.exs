defmodule Whiff.OptionsTest do
  use ExUnit.Case, async: true

  alias Whiff.Options

  defp invalid?(result), do: match?({:error, %Whiff.Error{reason: :invalid_option}}, result)

  test "defaults" do
    assert {:ok, opts} = Options.validate([])

    assert opts == %{
             profile: :standard,
             privacy: :strict,
             mode: :fallback,
             strict: false,
             plugin_timeout_ms: 5_000,
             provenance: false,
             tokens: 800,
             stage: :never
           }
  end

  test "non-keyword input returns an error instead of raising" do
    for bad <- [%{}, [:foo], [1], "x", [{"profile", :full}]] do
      assert invalid?(Options.validate(bad)), inspect(bad)
    end

    assert invalid?(Options.validate(limits: [1]))
    assert invalid?(Options.validate(limits: [{"max_depth", 1}]))
  end

  test "each entry point has its own allow-list" do
    assert {:error, %Whiff.Error{details: %{unknown: [:name, :tokens]}}} =
             Options.validate([name: "x", tokens: 10], :extract)

    assert {:error, %Whiff.Error{details: %{unknown: [:stage]}}} =
             Options.validate([stage: :local], :extract_binary)

    assert {:error, %Whiff.Error{details: %{unknown: [:extractors, :mode]}}} =
             Options.validate([extractors: [], mode: :augment], :llm)

    assert {:error, %Whiff.Error{details: %{unknown: [:max_concurrency]}}} =
             Options.validate([max_concurrency: 2], :extract)

    assert {:ok, _} =
             Options.validate([max_concurrency: 2, on_error: :halt, timeout: 10], :extract_many)

    assert {:ok, _} = Options.validate([name: "a.txt", mime: "text/plain"], :extract_binary)
    assert {:ok, _} = Options.validate([tokens: 10, stage: :local], :llm)
  end

  test "duplicates and name+filename are rejected" do
    assert {:error, %Whiff.Error{details: %{duplicate: [:profile]}}} =
             Options.validate(profile: :full, profile: :minimal)

    assert invalid?(Options.validate([name: "a", filename: "b"], :extract_binary))
  end

  test "scalar options" do
    valid = [
      profile: :minimal,
      privacy: :off,
      mode: :override,
      hashes: [:sha256, :sha256],
      only: ["text.plain"],
      skip: ["text.keywords"],
      format: "pdf",
      provenance: true,
      strict: true,
      plugin_timeout_ms: 1,
      override_fields: ["content.title", "format.myapp.trade"]
    ]

    assert {:ok, opts} = Options.validate(valid)
    assert opts.hashes == [:sha256]

    for {key, value} <- [
          profile: :turbo,
          privacy: :maybe,
          mode: :nope,
          hashes: [],
          hashes: [:md5],
          hashes: "sha256",
          only: [:atom],
          only: [""],
          skip: "x",
          format: :pdf,
          format: "",
          provenance: "yes",
          strict: 1,
          plugin_timeout_ms: 0,
          plugin_timeout_ms: 600_001,
          override_fields: ["title"],
          override_fields: ["content."],
          override_fields: [1],
          stage: :auto
        ] do
      assert invalid?(Options.validate([{key, value}])), "#{key}: #{inspect(value)}"
    end

    for {key, value} <- [tokens: 0, tokens: 100_001] do
      assert invalid?(Options.validate([{key, value}], :llm))
    end

    for {key, value} <- [max_concurrency: 0, on_error: :boom, timeout: 0, timeout: :never] do
      assert invalid?(Options.validate([{key, value}], :extract_many))
    end

    for {key, value} <- [name: :atom, filename: 1, mime: %{}] do
      assert invalid?(Options.validate([{key, value}], :extract_binary))
    end
  end

  test "plugin modules must implement the behaviour" do
    assert {:ok, _} =
             Options.validate(
               extractors: [Whiff.Test.TradeWhiffer],
               analyzers: [Whiff.Test.TitleAnalyzer]
             )

    assert {:error, %Whiff.Error{details: %{invalid: [Whiff.Test.NotAPlugin]}}} =
             Options.validate(extractors: [Whiff.Test.TradeWhiffer, Whiff.Test.NotAPlugin])

    assert invalid?(Options.validate(extractors: [Whiff.Test.TitleAnalyzer]))
    assert invalid?(Options.validate(analyzers: [Whiff.Test.TradeWhiffer]))
    assert invalid?(Options.validate(extractors: [Not.Loaded.Module]))
    assert invalid?(Options.validate(extractors: ["x"]))
    assert invalid?(Options.validate(analyzers: :nope))
  end

  describe "limits" do
    test "accepts every key at its cap and zero where meaningful" do
      assert {:ok, %{limits: limits}} = Options.validate(limits: Map.to_list(Options.limit_caps()))
      assert limits == Options.limit_caps()

      assert {:ok, _} = Options.validate(limits: [max_depth: 0, hash_max_bytes: 0, max_children: 0])
    end

    test "rejects over-cap, zero timeouts, negatives, and unknown keys" do
      for {key, cap} <- Options.limit_caps() do
        assert invalid?(Options.validate(limits: [{key, cap + 1}])), "#{key}"
      end

      nonzero = [:file_timeout_ms, :extractor_timeout_ms, :max_read_bytes, :max_decompressed_bytes]

      for key <- nonzero do
        assert invalid?(Options.validate(limits: [{key, 0}])), "#{key}"
      end

      assert invalid?(Options.validate(limits: [max_read_bytes: -1]))
      assert invalid?(Options.validate(limits: [file_timeout_ms: "soon"]))
      assert invalid?(Options.validate(limits: [not_a_limit: 1]))
      assert invalid?(Options.validate(limits: :not_a_list))
    end

    @tag :native
    test "Elixir caps match the native caps" do
      {:ok, json} = Whiff.Native.native_version()
      native = Jason.decode!(json)["limit_caps"]

      assert native == Map.new(Options.limit_caps(), fn {k, v} -> {Atom.to_string(k), v} end)
    end
  end

  test "to_native_json keeps native keys only" do
    {:ok, opts} =
      Options.validate(
        profile: :full,
        hashes: [:sha256],
        privacy: :off,
        provenance: true,
        mode: :augment,
        limits: [max_depth: 2]
      )

    assert Jason.decode!(Options.to_native_json(opts)) == %{
             "profile" => "full",
             "hashes" => ["sha256"],
             "privacy" => "off",
             "provenance" => true,
             "limits" => %{"max_depth" => 2},
             "tokens" => 800
           }
  end
end
