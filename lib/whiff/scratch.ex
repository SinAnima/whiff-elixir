defmodule Whiff.Scratch do
  @moduledoc false

  # Opt-in local staging for path APIs (`stage: :local`).
  #
  # The file is copied into a private job directory under `:scratch_dir`
  # before the DirtyCpu NIF opens it. Afterwards `restore_report/3` rewrites
  # the report fields that describe the copy so they describe the original.

  import Bitwise

  alias Whiff.Error

  @default_max_bytes 1_073_741_824
  @dir_mode 0o700
  @file_mode 0o600

  @type tag :: :original | {:staged, original :: Path.t(), staged :: Path.t()}

  @doc """
  Copy `path` to a private scratch directory when `opts.stage == :local`.

  Returns `{:ok, :original}` when staging is off, `{:ok, {:staged, original,
  staged}}` after a successful copy, or `{:error, %Whiff.Error{}}`. A failed
  stage leaves no files behind.
  """
  @spec stage(Path.t(), map()) :: {:ok, tag()} | {:error, Error.t()}
  def stage(path, opts) when is_binary(path) and is_map(opts) do
    case Map.get(opts, :stage, :never) do
      :never -> {:ok, :original}
      :local -> stage_local(path)
      other -> {:error, Error.new(:invalid_option, "invalid stage: #{inspect(other)}")}
    end
  end

  @doc "Path the NIF should open."
  @spec path(Path.t(), tag()) :: Path.t()
  def path(original, :original), do: original
  def path(_path, {:staged, _original, staged}), do: staged

  @doc "Remove the staged file and its job directory. Always returns `:ok`."
  @spec cleanup(tag()) :: :ok
  def cleanup(:original), do: :ok

  def cleanup({:staged, _original, staged}) do
    _ = File.rm_rf(Path.dirname(staged))
    :ok
  end

  @doc """
  Rewrite report fields that describe the scratch copy.

  * `source.path` → the original path
  * `temporal.filesystem` → original mtime/atime/ctime at second precision;
    `created` is removed (Elixir cannot read birth time)
  * `system.device` / `inode` / `links` → original values; `allocated_bytes`
    and `sparse` are removed
  * `security.mode` / `permissions` / `setuid` / `setgid` / `sticky` /
    `owner.uid` / `owner.gid` → original values; `owner.user`,
    `owner.group`, `acl`, and `xattrs` are removed

  A `diagnostics.warnings` entry records the substitution.
  """
  @spec restore_report(map(), tag()) :: map()
  def restore_report(report, :original), do: report

  def restore_report(report, {:staged, original, _staged}) when is_map(report) do
    case File.stat(original, time: :posix) do
      {:ok, stat} ->
        report
        |> put_in_map(["source", "path"], original)
        |> restore_temporal(stat)
        |> restore_system(stat)
        |> restore_security(stat)
        |> add_warning(
          "stage: :local: filesystem fields taken from the original at second precision; " <>
            "created, allocated_bytes, sparse, owner names, acl, and xattrs omitted"
        )

      {:error, _} ->
        report
        |> put_in_map(["source", "path"], original)
        |> add_warning(
          "stage: :local: original file could not be re-read; filesystem fields describe the copy"
        )
    end
  end

  @doc "Map an error raised for the staged path back to the original path."
  @spec restore_error(Error.t(), tag()) :: Error.t()
  def restore_error(%Error{} = err, :original), do: err

  def restore_error(%Error{} = err, {:staged, original, staged}) do
    %{err | path: original, message: String.replace(err.message, staged, original)}
  end

  defp stage_local(path) do
    with {:ok, stat} <- regular_file(path),
         :ok <- within_cap(stat.size, path),
         {:ok, root} <- ensure_root(scratch_dir()),
         {:ok, job_dir} <- make_job_dir(root),
         :ok <- verify_root(root, job_dir) |> cleanup_on_error(job_dir) do
      # Keep the original basename so native source.name and detection match.
      staged = Path.join(job_dir, Path.basename(path))

      case copy(path, staged, stat) do
        :ok ->
          {:ok, {:staged, path, staged}}

        {:error, _} = err ->
          _ = File.rm_rf(job_dir)
          err
      end
    end
  end

  defp scratch_dir do
    case Application.get_env(:whiff, :scratch_dir) do
      dir when is_binary(dir) and dir != "" -> dir
      _ -> Path.join(System.tmp_dir!(), "whiff-scratch")
    end
  end

  defp scratch_max_bytes do
    case Application.get_env(:whiff, :scratch_max_bytes, @default_max_bytes) do
      n when is_integer(n) and n > 0 -> n
      _ -> @default_max_bytes
    end
  end

  defp regular_file(path) do
    case File.stat(path, time: :posix) do
      {:ok, %{type: :regular} = stat} ->
        {:ok, stat}

      {:ok, %{type: type}} ->
        {:error,
         Error.new(:unsupported_input, "scratch staging requires a regular file, got #{type}",
           path: path
         )}

      {:error, reason} ->
        {:error, map_posix(reason, path, "stat")}
    end
  end

  defp within_cap(size, path) do
    max = scratch_max_bytes()

    if size > max do
      {:error,
       Error.new(:invalid_option, "file size #{size} exceeds scratch_max_bytes #{max}",
         path: path,
         details: %{size: size, scratch_max_bytes: max}
       )}
    else
      :ok
    end
  end

  # The root may already exist. It must be a real directory (not a symlink).
  defp ensure_root(root) do
    case File.lstat(root) do
      {:ok, %{type: :directory}} ->
        {:ok, root}

      {:ok, %{type: type}} ->
        {:error, Error.new(:native_error, "scratch_dir is a #{type}, not a directory", path: root)}

      {:error, :enoent} ->
        with :ok <- mkdir_p(root), :ok <- chmod(root, @dir_mode), do: {:ok, root}

      {:error, reason} ->
        {:error, map_posix(reason, root, "stat scratch_dir")}
    end
  end

  # Random name + plain mkdir: fails instead of reusing a pre-created directory.
  defp make_job_dir(root, attempts \\ 3)

  defp make_job_dir(root, 0),
    do:
      {:error,
       Error.new(:native_error, "could not create a unique scratch job directory", path: root)}

  defp make_job_dir(root, attempts) do
    name = "whiff-" <> Base.url_encode64(:crypto.strong_rand_bytes(12), padding: false)
    dir = Path.join(root, name)

    case File.mkdir(dir) do
      :ok ->
        with :ok <- chmod(dir, @dir_mode) |> cleanup_on_error(dir), do: {:ok, dir}

      {:error, :eexist} ->
        make_job_dir(root, attempts - 1)

      {:error, reason} ->
        {:error, map_posix(reason, root, "mkdir scratch job directory")}
    end
  end

  # On Unix the root must be owned by this OS user and not writable by
  # group/other, so another local user cannot read or swap staged copies.
  defp verify_root(root, job_dir) do
    with {:unix, _} <- :os.type(),
         {:ok, root_stat} <- File.lstat(root),
         {:ok, job_stat} <- File.lstat(job_dir) do
      cond do
        root_stat.uid != job_stat.uid ->
          {:error, Error.new(:eacces, "scratch_dir is owned by another user", path: root)}

        (root_stat.mode &&& 0o022) != 0 and (root_stat.mode &&& 0o1000) == 0 ->
          {:error,
           Error.new(:eacces, "scratch_dir is writable by group or other users", path: root)}

        true ->
          :ok
      end
    else
      {:win32, _} -> :ok
      {:error, reason} -> {:error, map_posix(reason, root, "stat scratch_dir")}
    end
  end

  defp copy(from, to, stat) do
    with :ok <- posix(File.cp(from, to), from, "copy to scratch"),
         :ok <- chmod(to, @file_mode) do
      # Carry mtime/atime so native time fields match the original (seconds).
      _ = File.touch(to, stat.mtime)
      :ok
    end
  end

  defp mkdir_p(dir), do: posix(File.mkdir_p(dir), dir, "mkdir scratch_dir")
  defp chmod(path, mode), do: posix(File.chmod(path, mode), path, "chmod scratch")

  defp posix(:ok, _path, _what), do: :ok
  defp posix({:error, reason}, path, what), do: {:error, map_posix(reason, path, what)}

  defp cleanup_on_error(:ok, _dir), do: :ok

  defp cleanup_on_error({:error, _} = err, dir) do
    _ = File.rm_rf(dir)
    err
  end

  defp map_posix(:enoent, path, what), do: Error.new(:enoent, "#{what}: no such file", path: path)

  defp map_posix(:eacces, path, what),
    do: Error.new(:eacces, "#{what}: permission denied", path: path)

  defp map_posix(reason, path, what),
    do: Error.new(:native_error, "#{what}: #{inspect(reason)}", path: path)

  defp restore_temporal(report, stat) do
    update_section(report, ["temporal", "filesystem"], fn fs ->
      fs
      |> Map.put("modified", rfc3339(stat.mtime))
      |> Map.put("accessed", rfc3339(stat.atime))
      |> put_ctime(stat)
      |> Map.delete("created")
    end)
  end

  # File.Stat.ctime is status-change time on Unix and creation time on Windows.
  defp put_ctime(fs, stat) do
    case :os.type() do
      {:unix, _} -> Map.put(fs, "changed", rfc3339(stat.ctime))
      _ -> Map.delete(fs, "changed")
    end
  end

  defp restore_system(report, stat) do
    update_section(report, ["system"], fn sys ->
      sys
      |> Map.put("device", stat.major_device)
      |> Map.put("inode", stat.inode)
      |> Map.put("links", stat.links)
      |> Map.drop(["allocated_bytes", "sparse"])
    end)
  end

  defp restore_security(report, stat) do
    update_section(report, ["security"], fn sec ->
      mode = stat.mode &&& 0o7777

      sec
      |> put_if_present("mode", "0" <> Integer.to_string(mode, 8))
      |> put_if_present("permissions", permissions(mode))
      |> put_if_present("setuid", (mode &&& 0o4000) != 0)
      |> put_if_present("setgid", (mode &&& 0o2000) != 0)
      |> put_if_present("sticky", (mode &&& 0o1000) != 0)
      |> put_if_present("owner", %{"uid" => stat.uid, "gid" => stat.gid})
      |> Map.drop(["acl", "xattrs"])
    end)
  end

  defp put_if_present(map, key, value) do
    if Map.has_key?(map, key), do: Map.put(map, key, value), else: map
  end

  defp permissions(mode) do
    [0o400, 0o200, 0o100, 0o040, 0o020, 0o010, 0o004, 0o002, 0o001]
    |> Enum.zip(~c"rwxrwxrwx")
    |> Enum.map(fn {bit, char} -> if (mode &&& bit) != 0, do: char, else: ?- end)
    |> List.to_string()
  end

  defp rfc3339(posix) when is_integer(posix) do
    posix |> DateTime.from_unix!() |> DateTime.to_iso8601()
  end

  defp update_section(report, path, fun) do
    case get_in(report, path) do
      section when is_map(section) -> put_in_map(report, path, fun.(section))
      _ -> report
    end
  end

  defp put_in_map(map, [key], value), do: Map.put(map, key, value)

  defp put_in_map(map, [key | rest], value) do
    child = Map.get(map, key)
    child = if is_map(child), do: child, else: %{}
    Map.put(map, key, put_in_map(child, rest, value))
  end

  defp add_warning(report, warning) do
    update_in_diagnostics(report, fn diag ->
      Map.put(diag, "warnings", List.wrap(diag["warnings"]) ++ [warning])
    end)
  end

  defp update_in_diagnostics(report, fun) do
    diag = Map.get(report, "diagnostics")
    diag = if is_map(diag), do: diag, else: %{}
    Map.put(report, "diagnostics", fun.(diag))
  end
end
