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
  end

  test "rejects over-cap limits" do
    assert {:error, %Whiff.Error{reason: :invalid_option}} =
             Options.validate(limits: [max_depth: 99])
  end

  test "to_native_json encodes atoms as strings" do
    {:ok, opts} = Options.validate(profile: :full, hashes: [:sha256], privacy: :off)
    json = Options.to_native_json(opts)
    assert Jason.decode!(json)["profile"] == "full"
    assert Jason.decode!(json)["hashes"] == ["sha256"]
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
               hashes: :all
             )

    assert opts.mode == :override
    assert opts.on_error == :halt

    assert {:error, %Whiff.Error{reason: :invalid_option}} = Options.validate(mode: :nope)
    assert {:error, %Whiff.Error{reason: :invalid_option}} = Options.validate(extractors: ["x"])
    assert {:error, %Whiff.Error{reason: :invalid_option}} = Options.validate(analyzers: "x")
    assert {:error, %Whiff.Error{reason: :invalid_option}} = Options.validate(only: [:atom])
    assert {:error, %Whiff.Error{reason: :invalid_option}} = Options.validate(skip: "x")
    assert {:error, %Whiff.Error{reason: :invalid_option}} = Options.validate(tokens: 0)
    assert {:error, %Whiff.Error{reason: :invalid_option}} = Options.validate(max_concurrency: 0)
    assert {:error, %Whiff.Error{reason: :invalid_option}} = Options.validate(on_error: :boom)
    assert {:error, %Whiff.Error{reason: :invalid_option}} = Options.validate(override_fields: [1])
  end
end
