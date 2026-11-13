defmodule WhiffTest do
  use ExUnit.Case, async: false

  @moduletag :native

  doctest Whiff

  @fixture Path.expand("fixtures/hello.txt", __DIR__)
  @missing Path.expand("fixtures/missing.txt", __DIR__)

  test "version/0 matches mix.exs" do
    assert Whiff.version() == Mix.Project.config()[:version]
  end

  test "native_version reports the locked crate version and schema" do
    {:ok, json} = Whiff.Native.native_version()
    info = Jason.decode!(json)

    assert info["whiff"] == Whiff.version()
    assert info["schema"] == "whiff/1"
    assert info["crate"] =~ ~r/^\d+\.\d+\.\d+$/
  end

  test "extract/2 returns a string-keyed report" do
    assert {:ok, report} = Whiff.extract(@fixture)
    assert report["whiff"]["schema"] == "whiff/1"
    assert report["identification"]["format"] == "text"
    assert all_string_keys?(report)
  end

  defp all_string_keys?(map) when is_map(map),
    do: Enum.all?(map, fn {k, v} -> is_binary(k) and all_string_keys?(v) end)

  defp all_string_keys?(list) when is_list(list), do: Enum.all?(list, &all_string_keys?/1)
  defp all_string_keys?(_), do: true

  test "bang and non-bang return the same error struct" do
    assert {:error, %Whiff.Error{reason: :enoent} = err} = Whiff.extract(@missing)
    assert ^err = assert_raise(Whiff.Error, fn -> Whiff.extract!(@missing) end)

    assert {:error, binary_err} = Whiff.extract_binary("x", nope: 1)
    assert ^binary_err = assert_raise(Whiff.Error, fn -> Whiff.extract_binary!("x", nope: 1) end)

    assert {:error, llm_err} = Whiff.llm(@missing)
    assert ^llm_err = assert_raise(Whiff.Error, fn -> Whiff.llm!(@missing) end)
  end

  test "malformed option shapes return errors, never raise" do
    for opts <- [[:foo], [1], [limits: [1]], [{"profile", :full}]] do
      assert {:error, %Whiff.Error{reason: :invalid_option}} = Whiff.extract(@fixture, opts)
      assert {:error, %Whiff.Error{reason: :invalid_option}} = Whiff.extract_binary("x", opts)
      assert {:error, %Whiff.Error{reason: :invalid_option}} = Whiff.llm(@fixture, opts)
      assert {:error, %Whiff.Error{reason: :invalid_option}} = Whiff.extract_many([@fixture], opts)
    end

    assert {:error, %Whiff.Error{reason: :invalid_option}} = Whiff.extract(@fixture, %{})
  end

  test "a corrupt file is a report with diagnostics, not an error" do
    assert {:ok, report} =
             Whiff.extract(Path.expand("fixtures/corrupt.pdf", __DIR__), hashes: :none)

    assert report["identification"]["format"] == "pdf"
    assert Enum.any?(report["diagnostics"]["extractors"], &(&1["status"] == "error"))
  end

  test "llm/2 returns a projection smaller than the report" do
    {:ok, report} = Whiff.extract(@fixture)
    {:ok, view} = Whiff.llm(@fixture, tokens: 100)
    assert byte_size(Jason.encode!(view)) < byte_size(Jason.encode!(report))
  end

  describe "extract_many/2" do
    test "collects every result in input order" do
      paths = [@fixture, @missing, 123]

      assert {:ok, [first, second, third]} =
               Whiff.extract_many(paths, hashes: :none, max_concurrency: 3)

      assert {@fixture, {:ok, %{"whiff" => _}}} = first
      assert {@missing, {:error, %Whiff.Error{reason: :enoent, path: @missing}}} = second
      assert {123, {:error, %Whiff.Error{reason: :unsupported_input}}} = third
    end

    test ":halt returns the first error with completed pairs" do
      assert {:error, %Whiff.Error{reason: :enoent, path: @missing, details: %{partial: partial}}} =
               Whiff.extract_many([@fixture, @missing, @fixture],
                 on_error: :halt,
                 max_concurrency: 1
               )

      assert [{@fixture, {:ok, _}}] = partial
    end

    test ":halt with no errors returns every pair" do
      assert {:ok, [{@fixture, {:ok, _}}, {@fixture, {:ok, _}}]} =
               Whiff.extract_many([@fixture, @fixture], on_error: :halt, hashes: :none)
    end

    test "a path over :timeout is killed and reported with its path" do
      slow = Path.expand("fixtures/hang.slow", __DIR__)

      assert {:ok, [{^slow, {:error, %Whiff.Error{reason: :timeout, path: ^slow}}}]} =
               Whiff.extract_many([slow],
                 extractors: [Whiff.Test.SlowExtractor],
                 plugin_timeout_ms: 5_000,
                 timeout: 100
               )
    end
  end

  test "regular schedulers stay responsive during heavy native work" do
    big = Path.join(System.tmp_dir!(), "whiff-big-#{System.unique_integer([:positive])}.bin")
    File.write!(big, :crypto.strong_rand_bytes(32 * 1024 * 1024))
    parent = self()

    try do
      pinger =
        spawn_link(fn ->
          gaps =
            Enum.map(1..100, fn _ ->
              t0 = System.monotonic_time(:millisecond)
              Process.sleep(2)
              System.monotonic_time(:millisecond) - t0
            end)

          send(parent, {:gaps, gaps})
        end)

      tasks = for _ <- 1..4, do: Task.async(fn -> Whiff.extract(big, hashes: :all) end)
      assert Enum.all?(Task.await_many(tasks, 60_000), &match?({:ok, _}, &1))
      assert_receive {:gaps, gaps}, 10_000

      # DirtyCpu should leave the BEAM responsive. Absolute max is flaky under
      # CI load (observed 143–347ms); a blocked scheduler would show multi-second gaps.
      max_gap = Enum.max(gaps)

      assert max_gap < 1_000,
             "max scheduler gap #{max_gap}ms (pinger #{inspect(pinger)})"
    after
      File.rm(big)
    end
  end

  test "a large binary is not retained in the report or in errors" do
    bytes = :crypto.strong_rand_bytes(16 * 1024 * 1024)

    assert {:ok, report} = Whiff.extract_binary(bytes, name: "blob.bin", hashes: :none)
    assert byte_size(:erlang.term_to_binary(report)) < 1024 * 1024

    assert {:error, err} = Whiff.extract_binary(bytes, nope: 1)
    assert byte_size(:erlang.term_to_binary(err)) < 1024
  end
end
