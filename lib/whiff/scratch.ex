defmodule Whiff.Scratch do
  @moduledoc false

  alias Whiff.Error

  @default_max_bytes 1_073_741_824

  @type tag :: :original | {:staged, Path.t()}

  @doc """
  Optionally copy `path` to the configured scratch directory.

  Returns `{:ok, :original}` when staging is off, or `{:ok, {:staged, staged_path}}`
  after a successful copy. Staging runs on the BEAM (outside DirtyCpu / the
  native limiter).
  """
  @spec stage(Path.t(), map()) :: {:ok, tag()} | {:error, Error.t()}
  def stage(path, opts) when is_binary(path) and is_map(opts) do
    case Map.get(opts, :stage, :never) do
      :never ->
        {:ok, :original}

      :local ->
        stage_local(path)

      other ->
        {:error, Error.new(:invalid_option, "invalid stage: #{inspect(other)}")}
    end
  end

  @doc "Resolve the path the NIF should open."
  @spec path(Path.t(), tag()) :: Path.t()
  def path(original, :original), do: original
  def path(_original, {:staged, staged}), do: staged

  @doc "Remove a staged file if present."
  @spec cleanup(tag()) :: :ok
  def cleanup(:original), do: :ok

  def cleanup({:staged, staged}) do
    _ = File.rm(staged)
    # Remove the unique job directory when empty (best-effort).
    _ = File.rmdir(Path.dirname(staged))
    :ok
  end

  defp stage_local(path) do
    with {:ok, stat} <- safe_stat(path),
         :ok <- within_cap(stat.size, path),
         root <- scratch_dir(),
         :ok <- ensure_dir(root),
         job_dir <- Path.join(root, "whiff-#{System.unique_integer([:positive])}"),
         :ok <- ensure_dir(job_dir),
         # Keep the original basename so native source.name / detection match the caller path.
         staged <- Path.join(job_dir, Path.basename(path)),
         :ok <- safe_copy(path, staged) do
      {:ok, {:staged, staged}}
    end
  end

  defp scratch_dir do
    case Application.get_env(:whiff, :scratch_dir) do
      nil -> Path.join(System.tmp_dir!(), "whiff-scratch")
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

  defp within_cap(size, path) do
    max = scratch_max_bytes()

    if size > max do
      {:error,
       Error.new(
         :invalid_option,
         "file size #{size} exceeds scratch_max_bytes #{max}",
         path: path,
         details: %{size: size, scratch_max_bytes: max}
       )}
    else
      :ok
    end
  end

  defp ensure_dir(dir) do
    case File.mkdir_p(dir) do
      :ok -> :ok
      {:error, reason} -> {:error, map_posix(reason, dir, "mkdir scratch_dir")}
    end
  end

  defp safe_stat(path) do
    case File.stat(path) do
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

  defp safe_copy(from, to) do
    case File.cp(from, to) do
      :ok -> :ok
      {:error, reason} -> {:error, map_posix(reason, from, "copy to scratch")}
    end
  end

  defp map_posix(:enoent, path, what),
    do: Error.new(:enoent, "#{what}: no such file", path: path)

  defp map_posix(:eacces, path, what),
    do: Error.new(:eacces, "#{what}: permission denied", path: path)

  defp map_posix(reason, path, what),
    do: Error.new(:native_error, "#{what}: #{inspect(reason)}", path: path)
end
