defmodule WhiffTest do
  use ExUnit.Case, async: false

  @moduletag :native

  @fixture Path.expand("fixtures/hello.txt", __DIR__)

  test "schema_version/0" do
    assert Whiff.schema_version() == "whiff/1"
  end

  test "version/0 returns a semver-ish string" do
    assert Whiff.version() =~ ~r/\d+\.\d+\.\d+/
  end

  test "extract/2 returns string-keyed map for text fixture" do
    assert {:ok, report} = Whiff.extract(@fixture)
    assert is_map(report)
    assert report["whiff"]["schema"] == "whiff/1"
    assert is_binary(report["identification"]["format"])
    refute Map.keys(report) |> Enum.any?(&is_atom/1)
  end

  test "extract!/2 returns report or raises Whiff.Error" do
    report = Whiff.extract!(@fixture)
    assert report["whiff"]["schema"] == "whiff/1"

    assert_raise Whiff.Error, fn ->
      Whiff.extract!("/definitely/missing-whiff-#{System.unique_integer([:positive])}.bin")
    end
  end

  test "missing file returns :enoent" do
    path = "/tmp/whiff-missing-#{System.unique_integer([:positive])}.bin"
    assert {:error, %Whiff.Error{reason: :enoent}} = Whiff.extract(path)
  end

  test "extract_binary/2 with name" do
    bytes = File.read!(@fixture)
    assert {:ok, report} = Whiff.extract_binary(bytes, name: "hello.txt")
    assert report["identification"]["format"]
  end

  test "llm/2 returns compact projection" do
    assert {:ok, compact} = Whiff.llm(@fixture, tokens: 800)
    assert is_map(compact)
  end

  test "llm!/2 and extract_binary!/2 bang variants" do
    assert is_map(Whiff.llm!(@fixture, tokens: 800))
    assert is_map(Whiff.extract_binary!(File.read!(@fixture), name: "hello.txt"))

    assert_raise Whiff.Error, fn -> Whiff.llm!(123) end
    assert_raise Whiff.Error, fn -> Whiff.extract_binary!(123) end
  end

  test "rejects non-binary extract paths and extract_many bad args" do
    assert {:error, %Whiff.Error{reason: :unsupported_input}} = Whiff.extract(123)
    assert {:error, %Whiff.Error{reason: :unsupported_input}} = Whiff.extract_binary(123)
    assert {:error, %Whiff.Error{reason: :unsupported_input}} = Whiff.extract_many("nope")
    assert {:error, %Whiff.Error{reason: :unsupported_input}} = Whiff.llm(123)
  end

  test "extract_many halt stops on first error" do
    missing = "/tmp/whiff-missing-halt-#{System.unique_integer([:positive])}.bin"

    assert {:error, %Whiff.Error{reason: :enoent, details: details}} =
             Whiff.extract_many([@fixture, missing], on_error: :halt, hashes: :none)

    assert is_list(details[:partial])
  end

  test "rejects unknown options" do
    assert {:error, %Whiff.Error{reason: :invalid_option}} =
             Whiff.extract(@fixture, nope: true)
  end

  test "rejects invalid profile" do
    assert {:error, %Whiff.Error{reason: :invalid_option}} =
             Whiff.extract(@fixture, profile: :turbo)
  end

  test "bang and non-bang share Whiff.Error" do
    path = "/tmp/whiff-missing-bang-#{System.unique_integer([:positive])}.bin"
    assert {:error, %Whiff.Error{reason: reason} = err} = Whiff.extract(path)

    raised =
      assert_raise Whiff.Error, fn ->
        Whiff.extract!(path)
      end

    assert raised.reason == reason
    assert raised.__struct__ == err.__struct__
  end

  test "partial diagnostics remain ok" do
    assert {:ok, report} = Whiff.extract(@fixture, profile: :minimal)
    assert is_map(report["diagnostics"])
  end

  test "scheduler stays responsive under concurrent extract", %{async: _} do
    parent = self()

    ping =
      Task.async(fn ->
        Enum.each(1..20, fn i ->
          send(parent, {:ping, i})
          Process.sleep(5)
        end)
      end)

    extract =
      Task.async(fn ->
        Enum.map(1..4, fn _ -> Whiff.extract(@fixture) end)
      end)

    assert Enum.all?(Task.await(extract, 60_000), &match?({:ok, _}, &1))
    Task.await(ping, 5_000)
    assert_received {:ping, 1}
  end
end
