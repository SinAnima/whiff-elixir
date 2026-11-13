defmodule Whiff.PluginTest do
  use ExUnit.Case, async: false

  @moduletag :plugin

  alias Whiff.Test.PatchExtractor

  @fixtures Path.expand("../fixtures", __DIR__)
  @trade Path.join(@fixtures, "sample.trade")
  @hello Path.join(@fixtures, "hello.txt")
  @secret Path.join(@fixtures, "secret.secret")
  @slow Path.join(@fixtures, "hang.slow")

  defp drop_timings(map) when is_map(map),
    do: map |> Map.drop(["ms", "elapsed_ms"]) |> Map.new(fn {k, v} -> {k, drop_timings(v)} end)

  defp drop_timings(list) when is_list(list), do: Enum.map(list, &drop_timings/1)
  defp drop_timings(other), do: other

  defp runs(report, id), do: Enum.filter(report["diagnostics"]["extractors"], &(&1["id"] == id))

  defp patch_run(patch, opts \\ []) do
    key = "patch-#{System.unique_integer([:positive])}"
    PatchExtractor.put(key, patch)

    Whiff.extract_binary(
      "plain text\n",
      Keyword.merge(
        [name: "x.txt", mime: key, extractors: [PatchExtractor], mode: :augment, hashes: :none],
        opts
      )
    )
  end

  describe ":fallback" do
    test "runs for a proprietary format native does not cover" do
      assert {:ok, report} =
               Whiff.extract(@trade, extractors: [Whiff.Test.TradeWhiffer], hashes: :none)

      assert report["format"]["test.trade"] == %{
               "trade_id" => "T-1001",
               "currency" => "USD",
               "qty" => "10",
               "price" => "42.5"
             }

      assert report["content"]["title"] == "Trade T-1001"
      assert [%{"status" => "ok", "version" => 1}] = runs(report, "test.trade")
    end

    test "does not run when native covers the format" do
      assert {:ok, report} =
               Whiff.extract(@hello, extractors: [Whiff.Test.TitleWhiffer], hashes: :none)

      assert runs(report, "test.title") == []
      refute report["content"]["title"] == "plugin title"
    end

    test "an unreadable file is reported and never handed to a fallback" do
      path =
        Path.join(System.tmp_dir!(), "whiff-noread-#{System.unique_integer([:positive])}.trade")

      File.write!(path, "TRADE/1
id=1
")
      File.chmod!(path, 0o000)

      try do
        # Skip when running as root, where permissions are not enforced.
        if File.read(path) == {:error, :eacces} do
          assert {:ok, report} = Whiff.extract(path, extractors: [Whiff.Test.TradeWhiffer])
          assert report["identification"]["format"] == "unreadable"
          assert Enum.any?(report["diagnostics"]["warnings"], &(&1 =~ "cannot open"))
          assert runs(report, "test.trade") == []
        end
      after
        File.chmod!(path, 0o600)
        File.rm!(path)
      end
    end

    test "two extractors writing the same field: the second is a recorded conflict" do
      assert {:ok, report} =
               Whiff.extract_binary("dup\n",
                 name: "x.dup",
                 extractors: [Whiff.Test.FirstDup, Whiff.Test.SecondDup],
                 hashes: :none
               )

      assert report["content"]["title"] == "first"
      assert report["format"]["test.first"] == %{"n" => 1}
      refute Map.has_key?(report["format"], "test.second")
      assert [%{"status" => "ok"}] = runs(report, "test.first")
      assert [%{"status" => "error", "error_kind" => "conflict"}] = runs(report, "test.second")
    end
  end

  describe ":augment and :override" do
    test "augment adds a namespace and keywords" do
      assert {:ok, report} =
               Whiff.extract(@hello,
                 extractors: [Whiff.Test.AugmentPdfWhiffer],
                 mode: :augment,
                 hashes: :none
               )

      assert report["format"]["test.pdf_augment"] == %{"reviewed" => true}
      assert "augmented" in report["content"]["keywords"]
    end

    test "override replaces a declared field" do
      {:ok, native} = Whiff.extract_binary("hello\n", name: "t.txt", hashes: :none)
      assert native["content"]["title"] != "plugin title"

      assert {:ok, report} =
               Whiff.extract_binary("hello\n",
                 name: "t.txt",
                 extractors: [Whiff.Test.TitleWhiffer],
                 mode: :override,
                 override_fields: ["content.title"],
                 hashes: :none
               )

      assert report["content"]["title"] == "plugin title"
    end

    test "override without a declaration is a recorded conflict when native set the field" do
      {:ok, report} = patch_run(%{"content" => %{"excerpt" => "replaced"}}, mode: :override)
      assert report["content"]["excerpt"] != "replaced"
      assert [%{"status" => "error", "error_kind" => "conflict"}] = runs(report, "test.patch")
    end
  end

  describe "analyzers" do
    test "run after extractors" do
      assert {:ok, report} =
               Whiff.extract(@trade,
                 extractors: [Whiff.Test.TradeWhiffer],
                 analyzers: [Whiff.Test.TitleAnalyzer],
                 hashes: :none
               )

      assert report["metadata"]["test.title_analyzer"] == %{"normalized_title" => "TRADE T-1001"}
    end

    test "can append risks with an elixir source" do
      assert {:ok, report} =
               Whiff.extract(@hello, analyzers: [Whiff.Test.RiskAnalyzer], hashes: :none)

      assert [%{"kind" => "custom_flag", "source" => "elixir:test.risk"}] =
               Enum.filter(report["security"]["risks"], &(&1["kind"] == "custom_flag"))

      assert [%{"version" => 2, "status" => "ok"}] = runs(report, "test.risk")
    end

    test "a raising analyzer is recorded; strict turns it into an error" do
      assert {:ok, report} =
               Whiff.extract(@hello, analyzers: [Whiff.Test.RaisingAnalyzer], hashes: :none)

      assert [
               %{
                 "status" => "error",
                 "error_kind" => "analyzer_error",
                 "error" => "plugin raised RuntimeError"
               }
             ] =
               runs(report, "test.raising_analyzer")

      assert {:error,
              %Whiff.Error{reason: :analyzer_error, details: %{plugin: "test.raising_analyzer"}}} =
               Whiff.extract(@hello,
                 analyzers: [Whiff.Test.RaisingAnalyzer],
                 strict: true,
                 hashes: :none
               )
    end
  end

  describe "failure containment" do
    test "a plugin that kills itself is recorded and the caller survives" do
      assert {:ok, report} =
               Whiff.extract(@hello,
                 extractors: [Whiff.Test.KillingExtractor],
                 mode: :augment,
                 hashes: :none
               )

      assert [%{"status" => "error", "error_kind" => "extractor_error"}] = runs(report, "test.kill")
    end

    test "a crash in a process linked to the plugin is recorded and the caller survives" do
      assert {:ok, report} =
               Whiff.extract(@hello,
                 extractors: [Whiff.Test.LinkedCrashExtractor],
                 mode: :augment,
                 hashes: :none
               )

      assert [%{"status" => "error"}] = runs(report, "test.linked_crash")
    end

    test "supports?/2 raising is recorded, and strict returns it" do
      assert {:ok, report} =
               Whiff.extract(@hello, extractors: [Whiff.Test.RaisingSupports], hashes: :none)

      assert [%{"status" => "error", "error" => "plugin raised RuntimeError"}] =
               runs(report, "test.raising_supports")

      assert {:error, %Whiff.Error{reason: :extractor_error}} =
               Whiff.extract(@hello,
                 extractors: [Whiff.Test.RaisingSupports],
                 strict: true,
                 hashes: :none
               )
    end

    test "timeout is recorded with error_kind timeout" do
      assert {:ok, report} =
               Whiff.extract(@slow,
                 extractors: [Whiff.Test.SlowExtractor],
                 plugin_timeout_ms: 50,
                 hashes: :none
               )

      assert [%{"status" => "error", "error_kind" => "timeout"}] = runs(report, "test.slow")
    end

    test "invalid id or an id that collides with a native extractor is recorded" do
      assert {:ok, report} =
               Whiff.extract(@hello,
                 extractors: [Whiff.Test.BadIdExtractor, Whiff.Test.NativeIdExtractor],
                 mode: :augment,
                 hashes: :none
               )

      assert [%{"status" => "error"}] = runs(report, "Whiff.Test.BadIdExtractor")

      assert [%{"status" => "error", "error_kind" => "conflict"}] =
               runs(report, "Whiff.Test.NativeIdExtractor")

      refute Map.has_key?(report["format"], "x.y")
    end
  end

  describe "contract violations" do
    test "an invalid version/0 is recorded" do
      assert {:ok, report} =
               Whiff.extract(@hello,
                 extractors: [Whiff.Test.BadVersionExtractor],
                 mode: :augment,
                 hashes: :none
               )

      assert [%{"status" => "error", "error" => "version/0 must return" <> _}] =
               runs(report, "Whiff.Test.BadVersionExtractor")
    end

    test "an analyzer returning a bare map is recorded by shape only" do
      assert {:ok, report} =
               Whiff.extract(@hello, analyzers: [Whiff.Test.BadReturnAnalyzer], hashes: :none)

      assert [%{"error_kind" => "analyzer_error", "error" => "analyzer returned a map" <> _}] =
               runs(report, "test.bad_return")
    end

    test "long plugin error messages are truncated on a character boundary" do
      assert {:ok, report} =
               Whiff.extract_binary("x\n",
                 name: "long.txt",
                 analyzers: [Whiff.Test.BadReturnAnalyzer],
                 hashes: :none
               )

      [run] = runs(report, "test.bad_return")
      assert String.valid?(run["error"])
      assert String.ends_with?(run["error"], "...")
      assert byte_size(run["error"]) <= 260
    end
  end

  describe "patch protection" do
    test "plugins cannot forge diagnostics or add sections" do
      {:ok, native} = Whiff.extract_binary("plain text\n", name: "x.txt", hashes: :none)

      for patch <- [
            %{"diagnostics" => %{"truncated" => true}},
            %{"diagnostics" => %{"extractors" => [%{"id" => "fake", "status" => "ok"}]}},
            %{"plugins" => %{"x" => 1}},
            %{"integrity" => %{"sha256" => "x"}}
          ] do
        {:ok, report} = patch_run(patch)
        assert report["diagnostics"]["truncated"] == native["diagnostics"]["truncated"]
        refute Map.has_key?(report, "plugins")
        assert [%{"status" => "error"}] = runs(report, "test.patch"), inspect(patch)
        refute Enum.any?(report["diagnostics"]["extractors"], &(&1["id"] == "fake"))
      end
    end

    test "oversized patches are rejected" do
      {:ok, report} = patch_run(%{"metadata" => %{"big.list" => List.duplicate("a", 100_000)}})
      assert [%{"status" => "error", "error_kind" => "invalid_report"}] = runs(report, "test.patch")
      refute Map.has_key?(report["metadata"], "big.list")
    end

    test "embedded children survive a plugin merge" do
      {:ok, native} = Whiff.extract(Path.join(@fixtures, "nested.zip"), hashes: :none)

      {:ok, merged} =
        Whiff.extract(Path.join(@fixtures, "nested.zip"),
          extractors: [Whiff.Test.TitleWhiffer, Whiff.Test.AugmentPdfWhiffer],
          mode: :augment,
          hashes: :none
        )

      assert drop_timings(merged["embedded"]) == drop_timings(native["embedded"])
      assert native["embedded"] != []
    end
  end

  describe "privacy" do
    @tag :privacy
    test "strict redacts secrets in plugin patches" do
      assert {:ok, report} =
               Whiff.extract(@secret, extractors: [Whiff.Test.SecretWhiffer], hashes: :none)

      assert report["content"]["excerpt"] ==
               "contact me at [redacted:email] [redacted:credential_assignment]"
    end

    test "off keeps plugin values" do
      assert {:ok, report} =
               Whiff.extract(@secret,
                 extractors: [Whiff.Test.SecretWhiffer],
                 privacy: :off,
                 hashes: :none
               )

      assert report["content"]["excerpt"] =~ "agent@example.com"
    end

    test "plugin output never leaks through error messages" do
      for name <- ~w(return.txt throw.txt raise.txt exit.txt error.txt) do
        {:ok, report} =
          Whiff.extract_binary("x\n",
            name: name,
            extractors: [Whiff.Test.LeakyExtractor],
            mode: :augment,
            hashes: :none
          )

        [run] = runs(report, "test.leaky")
        assert run["status"] == "error"
        refute run["error"] =~ "jane.doe@example.com", name
        refute run["error"] =~ "hunter2", name
      end
    end
  end

  describe "registration" do
    setup do
      previous = Application.get_env(:whiff, :extractors)
      on_exit(fn -> Application.put_env(:whiff, :extractors, previous) end)
    end

    test "app config registers extractors; a per-call list replaces it" do
      Application.put_env(:whiff, :extractors, [Whiff.Test.TradeWhiffer])
      assert {:ok, report} = Whiff.extract(@trade, hashes: :none)
      assert report["format"]["test.trade"]["trade_id"] == "T-1001"

      assert {:ok, report} = Whiff.extract(@trade, extractors: [], hashes: :none)
      refute Map.has_key?(report["format"], "test.trade")
    end

    test "invalid modules in app config return :invalid_option" do
      Application.put_env(:whiff, :extractors, [Whiff.Test.NotAPlugin])

      assert {:error, %Whiff.Error{reason: :invalid_option}} = Whiff.extract(@hello, hashes: :none)
    end
  end

  test "provenance records plugin paths in upstream shape" do
    assert {:ok, report} =
             Whiff.extract(@trade,
               extractors: [Whiff.Test.TradeWhiffer],
               provenance: true,
               hashes: :none
             )

    assert report["diagnostics"]["provenance"]["format.test.trade.trade_id"] == "elixir:test.trade"

    assert Enum.all?(report["diagnostics"]["provenance"], fn {_k, v} -> is_binary(v) end)
  end
end
