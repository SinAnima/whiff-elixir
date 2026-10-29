defmodule Whiff.FidelityTest do
  use ExUnit.Case, async: false

  @moduletag :native

  @fixtures Path.expand("../fixtures", __DIR__)

  defp fixture(name), do: Path.join(@fixtures, name)

  test "text / jpeg / pdf / zip / empty / corrupt / unicode" do
    for name <- ~w(hello.txt tiny.jpg tiny.pdf sample.zip empty.bin corrupt.pdf café.txt) do
      path = fixture(name)
      assert File.exists?(path), "missing fixture #{name}"
      assert {:ok, report} = Whiff.extract(path, hashes: :none, profile: :minimal)
      assert report["whiff"]["schema"] == "whiff/1"
      assert is_map(report["identification"])
    end
  end

  test "nested zip extracts without raising" do
    assert {:ok, report} = Whiff.extract(fixture("nested.zip"), profile: :standard, hashes: :none)
    assert report["whiff"]["schema"] == "whiff/1"
  end

  test "binary input with supplied filename" do
    bytes = File.read!(fixture("tiny.jpg"))
    assert {:ok, report} = Whiff.extract_binary(bytes, name: "photo.jpg", hashes: :none)
    assert report["source"]["name"] in ["photo.jpg", nil] or is_map(report["identification"])
  end

  test "directory path is an error or diagnostics — not a crash" do
    result = Whiff.extract(@fixtures)

    assert match?({:error, %Whiff.Error{}}, result) or match?({:ok, %{}}, result)
  end

  @tag :schema
  test "reports validate against vendored whiff/1 schema" do
    schema_path = Path.expand("../../priv/schemas/whiff-1.schema.json", __DIR__)

    # Upstream schema is draft 2020-12; ex_json_schema supports draft 4/6/7.
    # Remap the dialect URI so we can still exercise structural validation.
    schema =
      schema_path
      |> File.read!()
      |> Jason.decode!()
      |> Map.put("$schema", "http://json-schema.org/draft-07/schema#")
      |> ExJsonSchema.Schema.resolve()

    assert {:ok, report} = Whiff.extract(fixture("hello.txt"), hashes: :none)

    case ExJsonSchema.Validator.validate(schema, report) do
      :ok ->
        :ok

      {:error, errors} ->
        flunk("schema errors: #{inspect(errors, limit: 5)}")
    end
  end
end
