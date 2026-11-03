defmodule Whiff.ScratchTest do
  use ExUnit.Case, async: false

  @fixture Path.expand("../fixtures/hello.txt", __DIR__)

  setup do
    scratch =
      Path.join(System.tmp_dir!(), "whiff-scratch-test-#{System.unique_integer([:positive])}")

    prev_dir = Application.get_env(:whiff, :scratch_dir)
    prev_max = Application.get_env(:whiff, :scratch_max_bytes)

    Application.put_env(:whiff, :scratch_dir, scratch)
    Application.put_env(:whiff, :scratch_max_bytes, 1_073_741_824)
    File.rm_rf!(scratch)

    on_exit(fn ->
      File.rm_rf!(scratch)

      if prev_dir == nil do
        Application.delete_env(:whiff, :scratch_dir)
      else
        Application.put_env(:whiff, :scratch_dir, prev_dir)
      end

      if prev_max == nil do
        Application.delete_env(:whiff, :scratch_max_bytes)
      else
        Application.put_env(:whiff, :scratch_max_bytes, prev_max)
      end
    end)

    %{scratch: scratch}
  end

  test "stage: :never leaves original and creates no scratch files", %{scratch: scratch} do
    assert {:ok, report} = Whiff.extract(@fixture, stage: :never, hashes: :none)
    assert report["whiff"]["schema"] == "whiff/1"
    refute File.exists?(scratch)
  end

  test "stage: :local copies, extracts, and cleans up", %{scratch: scratch} do
    assert {:ok, report} = Whiff.extract(@fixture, stage: :local, hashes: :none)
    assert report["whiff"]["schema"] == "whiff/1"
    assert report["source"]["name"] == "hello.txt"

    # Staged file removed in after; dir may exist empty.
    leftovers =
      case File.ls(scratch) do
        {:ok, files} -> files
        {:error, :enoent} -> []
      end

    assert leftovers == []
  end

  test "stage: :local refuses files over scratch_max_bytes", %{scratch: scratch} do
    Application.put_env(:whiff, :scratch_max_bytes, 1)

    assert {:error, %Whiff.Error{reason: :invalid_option, message: message}} =
             Whiff.extract(@fixture, stage: :local)

    assert message =~ "scratch_max_bytes"
    refute File.exists?(scratch) or match?({:ok, [_ | _]}, File.ls(scratch))
  end

  test "llm/2 honors stage: :local cleanup", %{scratch: scratch} do
    assert {:ok, view} = Whiff.llm(@fixture, stage: :local, tokens: 200)
    assert is_map(view)

    leftovers =
      case File.ls(scratch) do
        {:ok, files} -> files
        {:error, :enoent} -> []
      end

    assert leftovers == []
  end

  test "Scratch.stage/2 and cleanup/1 round-trip", %{scratch: scratch} do
    assert {:ok, :original} = Whiff.Scratch.stage(@fixture, %{stage: :never})
    assert Whiff.Scratch.path(@fixture, :original) == @fixture

    assert {:ok, {:staged, staged} = tag} = Whiff.Scratch.stage(@fixture, %{stage: :local})
    assert String.starts_with?(staged, scratch)
    assert File.exists?(staged)

    Whiff.Scratch.cleanup(tag)
    refute File.exists?(staged)
  end
end
