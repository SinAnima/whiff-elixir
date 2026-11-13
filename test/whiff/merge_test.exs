defmodule Whiff.MergeTest do
  use ExUnit.Case, async: true

  doctest Whiff.Merge

  alias Whiff.Merge

  @base %{
    "whiff" => %{"schema" => "whiff/1"},
    "content" => %{"title" => "native", "keywords" => ["a"]},
    "metadata" => %{"native.key" => 1},
    "format" => %{"native.fmt" => %{"a" => 1}},
    "security" => %{"risks" => [%{"kind" => "macros", "source" => "office"}], "encrypted" => false},
    "temporal" => %{"created" => "old"},
    "diagnostics" => %{"warnings" => ["w0"], "extractors" => [], "truncated" => false}
  }

  defp conflict?(result), do: match?({:error, %Whiff.Error{reason: :conflict}}, result)
  defp invalid?(result), do: match?({:error, %Whiff.Error{reason: :invalid_report}}, result)

  describe "sections" do
    test "protected and unknown sections are rejected" do
      assert conflict?(Merge.merge(@base, %{"whiff" => %{"schema" => "x"}}))
      assert conflict?(Merge.merge(@base, %{"integrity" => %{}}))
      assert invalid?(Merge.merge(@base, %{"embedded" => [%{}]}))
      assert invalid?(Merge.merge(@base, %{"plugins" => %{"x" => 1}}))
      assert invalid?(Merge.merge(@base, %{"content" => "not-a-map"}))
    end

    test "diagnostics accepts only warnings, prefixed with the plugin id" do
      assert {:ok, merged} =
               Merge.merge(@base, %{"diagnostics" => %{"warnings" => ["w1"]}}, plugin_id: "demo")

      assert merged["diagnostics"]["warnings"] == ["w0", "elixir:demo: w1"]
      assert merged["diagnostics"]["truncated"] == false

      assert conflict?(Merge.merge(@base, %{"diagnostics" => %{"truncated" => true}}))
      assert conflict?(Merge.merge(@base, %{"diagnostics" => %{"extractors" => [%{"id" => "x"}]}}))
      assert invalid?(Merge.merge(@base, %{"diagnostics" => %{"warnings" => [1]}}))
    end
  end

  describe "security" do
    test "secrets and personal_data cannot be patched" do
      assert conflict?(Merge.merge(@base, %{"security" => %{"secrets" => %{}}}))
      assert conflict?(Merge.merge(@base, %{"security" => %{"personal_data" => %{}}}))
    end

    test "risks are appended with an elixir source, native risks kept" do
      risk = %{"kind" => "custom", "category" => "other", "severity" => "low", "source" => "spoof"}

      assert {:ok, merged} =
               Merge.merge(@base, %{"security" => %{"risks" => [risk]}}, plugin_id: "scan")

      assert [%{"source" => "office"}, %{"kind" => "custom", "source" => "elixir:scan"}] =
               merged["security"]["risks"]
    end

    test "invalid risk entries are rejected" do
      for bad <- [
            %{"category" => "other", "severity" => "low"},
            %{"kind" => "x", "category" => "nope", "severity" => "low"},
            %{"kind" => "x", "category" => "other", "severity" => "extreme"},
            %{"kind" => "x", "category" => "other", "severity" => "low", "extra" => 1},
            %{"kind" => "x", "category" => "other", "severity" => "low", "detail" => 1},
            "not a map"
          ] do
        assert invalid?(Merge.merge(@base, %{"security" => %{"risks" => [bad]}})), inspect(bad)
      end

      assert invalid?(Merge.merge(@base, %{"security" => %{"risks" => "x"}}))
    end

    test "other security keys can be added but never replaced, even under override" do
      assert {:ok, merged} = Merge.merge(@base, %{"security" => %{"signed" => true}})
      assert merged["security"]["signed"] == true

      assert conflict?(
               Merge.merge(@base, %{"security" => %{"encrypted" => true}},
                 mode: :override,
                 override_fields: ["security.encrypted"]
               )
             )

      assert {:ok, _} = Merge.merge(@base, %{"security" => %{"encrypted" => false}})
    end
  end

  describe "content" do
    test "keywords append and de-duplicate" do
      assert {:ok, merged} = Merge.merge(@base, %{"content" => %{"keywords" => ["a", "b"]}})
      assert merged["content"]["keywords"] == ["a", "b"]
    end

    test "augment keeps native scalars, fallback replaces them" do
      patch = %{"content" => %{"title" => "plugin", "extra" => 1}}

      assert {:ok, kept} = Merge.merge(@base, patch, mode: :augment)
      assert {kept["content"]["title"], kept["content"]["extra"]} == {"native", 1}

      assert {:ok, replaced} = Merge.merge(@base, patch, mode: :fallback)
      assert replaced["content"]["title"] == "plugin"
    end

    test "override requires a declared full path" do
      patch = %{"content" => %{"title" => "plugin"}}
      assert conflict?(Merge.merge(@base, patch, mode: :override))
      assert conflict?(Merge.merge(@base, patch, mode: :override, override_fields: ["title"]))

      assert {:ok, merged} =
               Merge.merge(@base, patch, mode: :override, override_fields: ["content.title"])

      assert merged["content"]["title"] == "plugin"
    end
  end

  describe "plugin ownership" do
    test "a value set by an earlier plugin is a conflict in every mode unless declared" do
      owned = MapSet.new(["content.title"])
      patch = %{"content" => %{"title" => "second"}}

      for mode <- [:augment, :fallback, :override] do
        assert conflict?(Merge.merge(@base, patch, mode: mode, owned: owned)), "#{mode}"
      end

      assert {:ok, merged} =
               Merge.merge(@base, patch,
                 mode: :override,
                 owned: owned,
                 override_fields: ["content.title"]
               )

      assert merged["content"]["title"] == "second"
    end

    test "an identical value is not a conflict" do
      owned = MapSet.new(["content.title"])
      assert {:ok, _} = Merge.merge(@base, %{"content" => %{"title" => "native"}}, owned: owned)
    end

    test "no-op patches write nothing" do
      patch = %{"content" => %{"keywords" => ["a"], "title" => "native"}}

      assert {:ok, merged, []} = Merge.merge_tracked(@base, patch, provenance: true)
      assert merged == @base
    end

    test "nested maps under an existing value merge recursively" do
      report = Map.put(@base, "physical", %{"image" => %{"width" => 1}})

      assert {:ok, merged, ["physical.image.height"]} =
               Merge.merge_tracked(report, %{"physical" => %{"image" => %{"height" => 2}}})

      assert merged["physical"]["image"] == %{"width" => 1, "height" => 2}
    end

    test "merge_tracked reports written leaf paths" do
      patch = %{
        "content" => %{"extra" => 1, "title" => "ignored"},
        "format" => %{"p.q" => %{"r" => 1}}
      }

      assert {:ok, _merged, written} = Merge.merge_tracked(@base, patch, mode: :augment)
      assert Enum.sort(written) == ["content.extra", "format.p.q.r"]
    end
  end

  describe "namespaces and trees" do
    test "existing metadata/format namespaces collide unless declared" do
      assert conflict?(Merge.merge(@base, %{"metadata" => %{"native.key" => 2}}))
      assert conflict?(Merge.merge(@base, %{"format" => %{"native.fmt" => %{"b" => 2}}}))

      assert {:ok, merged} =
               Merge.merge(@base, %{"metadata" => %{"native.key" => 2}},
                 mode: :override,
                 override_fields: ["metadata.native.key"]
               )

      assert merged["metadata"]["native.key"] == 2
    end

    test "tree sections add missing values and keep native values" do
      assert {:ok, added} = Merge.merge(@base, %{"system" => %{"os" => %{"arch" => "arm"}}})
      assert added["system"]["os"]["arch"] == "arm"

      assert {:ok, kept} = Merge.merge(@base, %{"temporal" => %{"created" => "new"}})
      assert kept["temporal"]["created"] == "old"

      assert conflict?(Merge.merge(@base, %{"temporal" => %{"created" => "new"}}, mode: :override))
    end
  end

  describe "validation" do
    test "rejects unsupported terms" do
      for value <- [:atom, self(), make_ref(), fn -> :ok end, %Whiff.Error{message: "x"}] do
        assert invalid?(Merge.merge(@base, %{"content" => %{"v" => value}})), inspect(value)
      end

      assert invalid?(Merge.merge(@base, %{content: %{"title" => "x"}}))
    end

    test "rejects oversized maps, depth, strings, node counts, and total bytes" do
      assert invalid?(Merge.merge(@base, %{"metadata" => Map.new(1..300, &{"k#{&1}", &1})}))

      deep = Enum.reduce(1..10, "leaf", fn i, acc -> %{"l#{i}" => acc} end)
      assert invalid?(Merge.merge(@base, %{"metadata" => %{"deep" => deep}}))

      assert invalid?(
               Merge.merge(@base, %{"metadata" => %{"big" => String.duplicate("a", 65 * 1024)}})
             )

      assert invalid?(Merge.merge(@base, %{"metadata" => %{"list" => List.duplicate(1, 20_000)}}))

      chunks = for i <- 1..20, into: %{}, do: {"c#{i}", String.duplicate("a", 60 * 1024)}
      assert invalid?(Merge.merge(@base, %{"metadata" => %{"x.y" => chunks}}))
    end
  end

  test "provenance uses upstream string shape for written paths only" do
    report = put_in(@base, ["diagnostics", "provenance"], %{"content.title" => "text.plain"})
    patch = %{"content" => %{"title" => "kept native", "extra" => 1}, "metadata" => %{"p.q" => 1}}

    assert {:ok, merged} = Merge.merge(report, patch, provenance: true, plugin_id: "demo")

    assert merged["diagnostics"]["provenance"] == %{
             "content.title" => "text.plain",
             "content.extra" => "elixir:demo",
             "metadata.p.q" => "elixir:demo"
           }
  end
end
