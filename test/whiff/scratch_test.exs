defmodule Whiff.ScratchTest do
  use ExUnit.Case, async: false

  import Bitwise

  alias Whiff.Scratch

  @fixture Path.expand("../fixtures/hello.txt", __DIR__)

  setup do
    scratch =
      Path.join(System.tmp_dir!(), "whiff-scratch-test-#{System.unique_integer([:positive])}")

    prev_dir = Application.get_env(:whiff, :scratch_dir)
    prev_max = Application.get_env(:whiff, :scratch_max_bytes)

    Application.put_env(:whiff, :scratch_dir, scratch)
    Application.put_env(:whiff, :scratch_max_bytes, 1_073_741_824)

    on_exit(fn ->
      File.chmod(scratch, 0o700)
      File.rm_rf!(scratch)
      restore(:scratch_dir, prev_dir)
      restore(:scratch_max_bytes, prev_max)
    end)

    %{scratch: scratch}
  end

  defp restore(key, nil), do: Application.delete_env(:whiff, key)
  defp restore(key, value), do: Application.put_env(:whiff, key, value)

  defp entries(dir) do
    case File.ls(dir) do
      {:ok, files} -> files
      {:error, :enoent} -> []
    end
  end

  # Fields expected to differ between two extractions of the same file.
  defp comparable(report) do
    report
    |> update_in(["diagnostics"], &Map.drop(&1, ["elapsed_ms", "warnings"]))
    |> update_in(["diagnostics", "extractors"], fn runs -> Enum.map(runs, &Map.delete(&1, "ms")) end)
    |> update_in(["temporal", "filesystem"], &Map.drop(&1, ["created", "accessed"]))
    |> update_in(["system"], &Map.drop(&1, ["allocated_bytes", "sparse"]))
    |> update_in(["security"], &Map.drop(&1, ["acl", "xattrs", "owner"]))
  end

  defp truncate_times(report) do
    update_in(report, ["temporal", "filesystem"], fn fs ->
      Map.new(fs, fn {k, v} -> {k, String.replace(v, ~r/\.\d+Z$/, "Z")} end)
    end)
  end

  test "stage: :never creates no scratch files", %{scratch: scratch} do
    assert {:ok, _} = Whiff.extract(@fixture, stage: :never, hashes: :none)
    refute File.exists?(scratch)
  end

  test "a staged report describes the original file", %{scratch: scratch} do
    {:ok, direct} = Whiff.extract(@fixture, hashes: :none)
    {:ok, staged} = Whiff.extract(@fixture, stage: :local, hashes: :none)

    assert staged["source"]["path"] == @fixture
    assert comparable(staged) == comparable(truncate_times(direct))

    assert [warning] =
             staged["diagnostics"]["warnings"] -- List.wrap(direct["diagnostics"]["warnings"])

    assert warning =~ "stage: :local"
    assert entries(scratch) == []
  end

  test "errors refer to the original path" do
    tag = {:staged, "/data/a.txt", "/scratch/whiff-x/a.txt"}

    err =
      Whiff.Error.new(:native_error, "/scratch/whiff-x/a.txt: bad", path: "/scratch/whiff-x/a.txt")

    assert %Whiff.Error{path: "/data/a.txt", message: "/data/a.txt: bad"} =
             Scratch.restore_error(err, tag)
  end

  test "refuses files over scratch_max_bytes and leaves nothing behind", %{scratch: scratch} do
    Application.put_env(:whiff, :scratch_max_bytes, 1)

    assert {:error, %Whiff.Error{reason: :invalid_option, message: message}} =
             Whiff.extract(@fixture, stage: :local)

    assert message =~ "scratch_max_bytes"
    assert entries(scratch) == []
  end

  test "llm/2 stages and cleans up", %{scratch: scratch} do
    assert {:ok, view} = Whiff.llm(@fixture, stage: :local, tokens: 200)
    assert is_map(view)
    assert entries(scratch) == []
  end

  @tag :unix
  test "directories are private and job names are random", %{scratch: scratch} do
    assert {:ok, {:staged, @fixture, staged} = tag} = Scratch.stage(@fixture, %{stage: :local})
    job_dir = Path.dirname(staged)

    assert Path.dirname(job_dir) == scratch
    assert Path.basename(job_dir) =~ ~r/^whiff-[A-Za-z0-9_-]{16}$/
    assert (File.stat!(scratch).mode &&& 0o777) == 0o700
    assert (File.stat!(job_dir).mode &&& 0o777) == 0o700
    assert (File.stat!(staged).mode &&& 0o777) == 0o600
    assert File.stat!(staged, time: :posix).mtime == File.stat!(@fixture, time: :posix).mtime

    Scratch.cleanup(tag)
    refute File.exists?(job_dir)
  end

  @tag :unix
  test "refuses a scratch_dir writable by other users", %{scratch: scratch} do
    File.mkdir_p!(scratch)
    File.chmod!(scratch, 0o777)

    assert {:error, %Whiff.Error{reason: :eacces}} = Scratch.stage(@fixture, %{stage: :local})
    assert entries(scratch) == []
  end

  @tag :unix
  test "refuses a scratch_dir that is a symlink", %{scratch: scratch} do
    target = scratch <> "-target"
    File.mkdir_p!(target)
    File.ln_s!(target, scratch)

    try do
      assert {:error, %Whiff.Error{reason: :native_error, message: message}} =
               Scratch.stage(@fixture, %{stage: :local})

      assert message =~ "symlink"
    after
      File.rm!(scratch)
      File.rm_rf!(target)
    end
  end

  test "rejects invalid stage values, missing paths, and directories" do
    assert {:error, %Whiff.Error{reason: :invalid_option}} =
             Scratch.stage(@fixture, %{stage: :auto})

    missing =
      Path.join(System.tmp_dir!(), "whiff-missing-#{System.unique_integer([:positive])}.bin")

    assert {:error, %Whiff.Error{reason: :enoent}} = Scratch.stage(missing, %{stage: :local})

    assert {:error, %Whiff.Error{reason: :unsupported_input}} =
             Scratch.stage(Path.dirname(@fixture), %{stage: :local})
  end

  test "bad config falls back to defaults" do
    Application.put_env(:whiff, :scratch_dir, "")
    Application.put_env(:whiff, :scratch_max_bytes, -1)

    assert {:ok, {:staged, _, staged} = tag} = Scratch.stage(@fixture, %{stage: :local})
    assert staged =~ Path.join(System.tmp_dir!(), "whiff-scratch")
    Scratch.cleanup(tag)
  end

  test "mkdir failure when scratch_dir's parent is a file" do
    blocker = Path.join(System.tmp_dir!(), "whiff-block-#{System.unique_integer([:positive])}")
    File.write!(blocker, "x")
    Application.put_env(:whiff, :scratch_dir, Path.join(blocker, "child"))

    try do
      assert {:error, %Whiff.Error{reason: :native_error}} =
               Scratch.stage(@fixture, %{stage: :local})
    after
      File.rm(blocker)
    end
  end
end
