defmodule Whiff.OptionsTest do
  use ExUnit.Case, async: true

  alias Whiff.Options

  test "accepts known options" do
    assert {:ok, opts} =
             Options.validate(
               profile: :minimal,
               hashes: :none,
               privacy: :strict,
               limits: [max_depth: 1, file_timeout_ms: 1000]
             )

    assert opts.profile == :minimal
    assert opts.hashes == :none
  end

  test "rejects unknown option names" do
    assert {:error, %Whiff.Error{reason: :invalid_option, details: %{unknown: [:foo]}}} =
             Options.validate(foo: 1)
  end

  test "rejects bad hashes" do
    assert {:error, %Whiff.Error{reason: :invalid_option}} = Options.validate(hashes: [:md5])
    assert {:error, %Whiff.Error{reason: :invalid_option}} = Options.validate(hashes: "sha256")
  end

  test "rejects over-cap and invalid limits" do
    assert {:error, %Whiff.Error{reason: :invalid_option}} =
             Options.validate(limits: [max_depth: 99])

    assert {:error, %Whiff.Error{reason: :invalid_option}} =
             Options.validate(limits: [max_read_bytes: -1])

    assert {:error, %Whiff.Error{reason: :invalid_option}} =
             Options.validate(limits: [file_timeout_ms: "soon"])

    assert {:error, %Whiff.Error{reason: :invalid_option}} =
             Options.validate(limits: :not_a_list)
  end

  test "to_native_json encodes atoms, lists, maps, and booleans" do
    {:ok, opts} =
      Options.validate(
        profile: :full,
        hashes: [:sha256],
        privacy: :off,
        provenance: true,
        limits: [max_depth: 2, max_text_bytes: 100]
      )

    decoded = Jason.decode!(Options.to_native_json(opts))
    assert decoded["profile"] == "full"
    assert decoded["hashes"] == ["sha256"]
    assert decoded["privacy"] == "off"
    assert decoded["provenance"] == true
    assert decoded["limits"]["max_depth"] == 2
  end

  test "rejects non-keyword options and unknown limits" do
    assert {:error, %Whiff.Error{reason: :invalid_option}} = Options.validate(%{})

    assert {:error, %Whiff.Error{reason: :invalid_option}} =
             Options.validate(limits: [not_a_limit: 1])
  end

  test "validates modes, extractors, analyzers, and concurrency" do
    assert {:ok, opts} =
             Options.validate(
               mode: :override,
               extractors: [Whiff.Test.TradeWhiffer],
               analyzers: [Whiff.Test.TitleAnalyzer],
               max_concurrency: 2,
               on_error: :halt,
               override_fields: ["content.title"],
               only: ["identification"],
               skip: ["embedded"],
               format: "text/plain",
               provenance: true,
               strict: true,
               tokens: 100,
               plugin_timeout_ms: 1000,
               name: "x.bin",
               filename: "y.bin",
               mime: "application/octet-stream",
               hashes: :all,
               stage: :local
             )

    assert opts.mode == :override
    assert opts.on_error == :halt
    assert opts.stage == :local
    assert opts.filename == "y.bin"
    assert opts.mime == "application/octet-stream"

    assert {:error, %Whiff.Error{reason: :invalid_option}} = Options.validate(mode: :nope)
    assert {:error, %Whiff.Error{reason: :invalid_option}} = Options.validate(extractors: ["x"])
    assert {:error, %Whiff.Error{reason: :invalid_option}} = Options.validate(extractors: :nope)
    assert {:error, %Whiff.Error{reason: :invalid_option}} = Options.validate(analyzers: "x")
    assert {:error, %Whiff.Error{reason: :invalid_option}} = Options.validate(analyzers: [:ok, "x"])
    assert {:error, %Whiff.Error{reason: :invalid_option}} = Options.validate(only: [:atom])
    assert {:error, %Whiff.Error{reason: :invalid_option}} = Options.validate(only: "x")
    assert {:error, %Whiff.Error{reason: :invalid_option}} = Options.validate(skip: "x")
    assert {:error, %Whiff.Error{reason: :invalid_option}} = Options.validate(skip: [1])
    assert {:error, %Whiff.Error{reason: :invalid_option}} = Options.validate(tokens: 0)
    assert {:error, %Whiff.Error{reason: :invalid_option}} = Options.validate(max_concurrency: 0)
    assert {:error, %Whiff.Error{reason: :invalid_option}} = Options.validate(on_error: :boom)
    assert {:error, %Whiff.Error{reason: :invalid_option}} = Options.validate(override_fields: [1])
    assert {:error, %Whiff.Error{reason: :invalid_option}} = Options.validate(override_fields: :x)
  end

  test "rejects invalid scalars and stage" do
    assert {:error, %Whiff.Error{reason: :invalid_option}} = Options.validate(profile: :turbo)
    assert {:error, %Whiff.Error{reason: :invalid_option}} = Options.validate(privacy: :maybe)
    assert {:error, %Whiff.Error{reason: :invalid_option}} = Options.validate(format: :pdf)
    assert {:error, %Whiff.Error{reason: :invalid_option}} = Options.validate(provenance: "yes")
    assert {:error, %Whiff.Error{reason: :invalid_option}} = Options.validate(strict: "yes")
    assert {:error, %Whiff.Error{reason: :invalid_option}} = Options.validate(plugin_timeout_ms: 0)
    assert {:error, %Whiff.Error{reason: :invalid_option}} = Options.validate(stage: :auto)
    assert {:error, %Whiff.Error{reason: :invalid_option}} = Options.validate(name: :atom)
    assert {:error, %Whiff.Error{reason: :invalid_option}} = Options.validate(filename: 1)
    assert {:error, %Whiff.Error{reason: :invalid_option}} = Options.validate(mime: %{})

    assert {:ok, %{stage: :never}} = Options.validate([])
  end
end
