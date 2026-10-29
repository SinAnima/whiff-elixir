defmodule Whiff.MergeTest do
  use ExUnit.Case, async: true

  alias Whiff.Merge

  @base %{
    "whiff" => %{"schema" => "whiff/1"},
    "content" => %{"title" => "native"},
    "metadata" => %{"native_key" => 1},
    "format" => %{"native_fmt" => %{"a" => 1}},
    "security" => %{"risks" => ["x"]},
    "diagnostics" => %{"warnings" => ["w0"], "extractors" => []}
  }

  test "rejects non-map arguments" do
    assert {:error, %Whiff.Error{reason: :invalid_report}} = Merge.merge("nope", %{}, [])
  end

  test "rejects protected top-level sections" do
    assert {:error, %Whiff.Error{reason: :conflict}} =
             Merge.merge(@base, %{"whiff" => %{"schema" => "x"}}, mode: :augment)

    assert {:error, %Whiff.Error{reason: :conflict}} =
             Merge.merge(@base, %{"integrity" => %{}}, mode: :augment)
  end

  test "rejects security risks/secrets/personal_data replacements" do
    assert {:error, %Whiff.Error{reason: :conflict}} =
             Merge.merge(@base, %{"security" => %{"risks" => []}}, mode: :augment)
  end

  test "allows soft security fields via deep merge" do
    assert {:ok, report} =
             Merge.merge(@base, %{"security" => %{"notes" => "ok"}}, mode: :augment)

    assert get_in(report, ["security", "notes"]) == "ok"
    assert get_in(report, ["security", "risks"]) == ["x"]
  end

  test "merges diagnostics warnings and extractors" do
    patch = %{
      "diagnostics" => %{
        "warnings" => ["w1"],
        "limits_hit" => ["depth"],
        "extractors" => [%{"id" => "p"}],
        "extra" => true
      }
    }

    assert {:ok, report} = Merge.merge(@base, patch, mode: :augment)
    assert "w0" in report["diagnostics"]["warnings"]
    assert "w1" in report["diagnostics"]["warnings"]
    assert "depth" in report["diagnostics"]["limits_hit"]
    assert report["diagnostics"]["extra"] == true
    assert Enum.any?(report["diagnostics"]["extractors"], &(&1["id"] == "p"))
  end

  test "content keywords dedupe and fallback replaces scalars" do
    report = Map.put(@base, "content", %{"title" => "native", "keywords" => ["a"]})

    assert {:ok, merged} =
             Merge.merge(report, %{"content" => %{"keywords" => ["a", "b"], "title" => "plugin"}},
               mode: :fallback
             )

    assert merged["content"]["title"] == "plugin"
    assert merged["content"]["keywords"] == ["a", "b"]
  end

  test "content augment keeps native scalars" do
    assert {:ok, merged} =
             Merge.merge(@base, %{"content" => %{"title" => "plugin", "extra" => 1}},
               mode: :augment
             )

    assert merged["content"]["title"] == "native"
    assert merged["content"]["extra"] == 1
  end

  test "content override requires declared fields" do
    assert {:error, %Whiff.Error{reason: :conflict}} =
             Merge.merge(@base, %{"content" => %{"title" => "plugin"}}, mode: :override)

    assert {:ok, merged} =
             Merge.merge(@base, %{"content" => %{"title" => "plugin"}},
               mode: :override,
               override_fields: ["content.title"]
             )

    assert merged["content"]["title"] == "plugin"
  end

  test "metadata namespace collision and override" do
    assert {:error, %Whiff.Error{reason: :conflict}} =
             Merge.merge(@base, %{"metadata" => %{"native_key" => 2}}, mode: :augment)

    assert {:ok, merged} =
             Merge.merge(@base, %{"metadata" => %{"native_key" => 2}},
               mode: :override,
               override_fields: ["metadata.native_key"]
             )

    assert merged["metadata"]["native_key"] == 2
  end

  test "deep merge nested maps and override leaf collision" do
    # format/metadata are namespaced: colliding top keys error
    assert {:error, %Whiff.Error{reason: :conflict}} =
             Merge.merge(@base, %{"format" => %{"native_fmt" => %{"nested" => %{"y" => 2}}}},
               mode: :augment
             )

    assert {:ok, merged} =
             Merge.merge(@base, %{"format" => %{"plugin_fmt" => %{"nested" => %{"y" => 2}}}},
               mode: :augment
             )

    assert get_in(merged, ["format", "plugin_fmt", "nested", "y"]) == 2

    assert {:ok, overridden} =
             Merge.merge(@base, %{"temporal" => %{"created" => "now"}}, mode: :augment)

    assert overridden["temporal"]["created"] == "now"

    report2 = Map.put(@base, "temporal", %{"created" => "old"})

    assert {:ok, kept} =
             Merge.merge(report2, %{"temporal" => %{"created" => "new"}}, mode: :augment)

    assert kept["temporal"]["created"] == "old"

    assert {:error, %Whiff.Error{reason: :conflict}} =
             Merge.merge(report2, %{"temporal" => %{"created" => "new"}}, mode: :override)

    assert {:ok, forced} =
             Merge.merge(report2, %{"temporal" => %{"created" => "new"}},
               mode: :override,
               override_fields: ["temporal.created"]
             )

    assert forced["temporal"]["created"] == "new"

    # nested deep_merge under a non-namespaced section
    report3 = Map.put(@base, "system", %{"os" => %{"name" => "mac"}})

    assert {:ok, deep} =
             Merge.merge(report3, %{"system" => %{"os" => %{"arch" => "arm"}}}, mode: :augment)

    assert get_in(deep, ["system", "os", "name"]) == "mac"
    assert get_in(deep, ["system", "os", "arch"]) == "arm"
  end

  test "rejects unsupported section types and invalid terms" do
    assert {:error, %Whiff.Error{reason: :invalid_report}} =
             Merge.merge(@base, %{"content" => "not-a-map"}, mode: :augment)

    assert {:error, %Whiff.Error{reason: :invalid_report}} =
             Merge.merge(@base, %{"content" => %{"title" => :atom}}, mode: :augment)

    assert {:error, %Whiff.Error{reason: :invalid_report}} =
             Merge.merge(@base, %{"content" => %{"title" => self()}}, mode: :augment)

    assert {:error, %Whiff.Error{reason: :invalid_report}} =
             Merge.merge(@base, %{"content" => %{"box" => %Whiff.Error{message: "x", reason: :x}}},
               mode: :augment
             )
  end

  test "rejects oversized maps, depth, and strings" do
    big_map = Map.new(1..300, fn i -> {"k#{i}", i} end)

    assert {:error, %Whiff.Error{reason: :invalid_report}} =
             Merge.merge(@base, %{"metadata" => big_map}, mode: :augment)

    deep =
      Enum.reduce(1..10, "leaf", fn i, acc -> %{"l#{i}" => acc} end)

    assert {:error, %Whiff.Error{reason: :invalid_report}} =
             Merge.merge(@base, %{"metadata" => %{"deep" => deep}}, mode: :augment)

    huge = String.duplicate("a", 65 * 1024)

    assert {:error, %Whiff.Error{reason: :invalid_report}} =
             Merge.merge(@base, %{"metadata" => %{"big" => huge}}, mode: :augment)
  end

  test "provenance annotates plugin paths without clobbering native" do
    report =
      put_in(@base, ["diagnostics", "provenance"], %{
        "content.title" => %{"source" => "native"}
      })

    assert {:ok, merged} =
             Merge.merge(
               report,
               %{"content" => %{"extra" => 1}, "metadata" => %{"p" => %{"q" => 1}}},
               mode: :augment,
               provenance: true,
               plugin_id: "demo"
             )

    prov = get_in(merged, ["diagnostics", "provenance"])
    assert prov["content.title"]["source"] == "native"
    assert prov["content.extra"]["source"] == "elixir:demo"
    assert prov["metadata.p.q"]["source"] == "elixir:demo"
  end

  test "validate_patch accepts lists of scalars" do
    assert :ok = Merge.validate_patch(["a", 1, true, nil], 0)
  end
end
