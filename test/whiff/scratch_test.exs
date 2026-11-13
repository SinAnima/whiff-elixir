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
    assert Whiff.Scratch.cleanup(:original) == :ok

    assert {:ok, {:staged, staged} = tag} = Whiff.Scratch.stage(@fixture, %{stage: :local})
    assert String.starts_with?(staged, scratch)
    assert File.exists?(staged)

    Whiff.Scratch.cleanup(tag)
    refute File.exists?(staged)
  end

  test "stage rejects invalid stage atom and missing paths" do
    assert {:error, %Whiff.Error{reason: :invalid_option}} =
             Whiff.Scratch.stage(@fixture, %{stage: :auto})

    missing =
      Path.join(System.tmp_dir!(), "whiff-missing-#{System.unique_integer([:positive])}.bin")

    assert {:error, %Whiff.Error{reason: :enoent}} =
             Whiff.Scratch.stage(missing, %{stage: :local})
  end

  test "stage rejects non-regular files" do
    dir = Path.join(System.tmp_dir!(), "whiff-dir-#{System.unique_integer([:positive])}")
    File.mkdir_p!(dir)

    try do
      assert {:error, %Whiff.Error{reason: :unsupported_input}} =
               Whiff.Scratch.stage(dir, %{stage: :local})
    after
      File.rmdir(dir)
    end
  end

  test "scratch_dir and scratch_max_bytes fall back on bad config", %{scratch: scratch} do
    Application.put_env(:whiff, :scratch_dir, "")
    Application.put_env(:whiff, :scratch_max_bytes, -1)

    assert {:ok, {:staged, staged} = tag} = Whiff.Scratch.stage(@fixture, %{stage: :local})
    refute String.starts_with?(staged, scratch)
    assert String.contains?(staged, "whiff-scratch")
    Whiff.Scratch.cleanup(tag)

    Application.put_env(:whiff, :scratch_dir, :not_a_path)
    assert {:ok, {:staged, staged2} = tag2} = Whiff.Scratch.stage(@fixture, %{stage: :local})
    Whiff.Scratch.cleanup(tag2)
    assert is_binary(staged2)
  end

  test "mkdir failure when scratch_dir parent is a file" do
    blocker = Path.join(System.tmp_dir!(), "whiff-block-#{System.unique_integer([:positive])}")
    File.write!(blocker, "x")
    Application.put_env(:whiff, :scratch_dir, Path.join(blocker, "child"))

    try do
      assert {:error, %Whiff.Error{reason: reason}} =
               Whiff.Scratch.stage(@fixture, %{stage: :local})

      assert reason in [:native_error, :eacces, :enoent]
    after
      File.rm(blocker)
    end
  end
end
