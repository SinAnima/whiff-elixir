defmodule Whiff.Plugin do
  @moduledoc false

  # Runs plugin callbacks in an isolated, unlinked process.
  #
  # * The worker is not linked to the caller: a plugin that exits, is killed,
  #   or crashes a linked process cannot take the caller down.
  # * A guard process kills the worker if the caller exits first, so
  #   abandoned plugin work does not keep running.
  # * Error messages never include plugin-returned values, thrown values, or
  #   exception messages, which may contain extracted content.

  alias Whiff.Error

  @doc """
  Run `fun` with a timeout.

  Options: `:timeout` (ms, default 5000), `:kind` (`:extractor` | `:analyzer`),
  `:id` (plugin id used in error details).

  Returns `{:ok, value}` or `{:error, %Whiff.Error{}}` for raise, throw, exit,
  kill, or timeout.
  """
  @spec run((-> term()), keyword()) :: {:ok, term()} | {:error, Error.t()}
  def run(fun, opts \\ []) when is_function(fun, 0) do
    timeout = Keyword.get(opts, :timeout, 5_000)
    kind = Keyword.get(opts, :kind, :extractor)
    id = Keyword.get(opts, :id, "plugin")
    caller = self()
    ref = make_ref()

    {pid, mon} = spawn_monitor(fn -> send(caller, {ref, invoke(fun, kind, id)}) end)
    guard = spawn(fn -> guard(caller, pid) end)

    result =
      receive do
        {^ref, result} ->
          result

        {:DOWN, ^mon, :process, ^pid, reason} ->
          {:error,
           Error.new(reason_for(kind), "plugin process exited (#{exit_kind(reason)})",
             details: %{plugin: id}
           )}
      after
        timeout ->
          Process.exit(pid, :kill)

          {:error,
           Error.new(:timeout, "plugin timed out after #{timeout}ms", details: %{plugin: id})}
      end

    Process.demonitor(mon, [:flush])
    Process.exit(guard, :kill)
    flush(ref)
    result
  end

  defp invoke(fun, kind, id) do
    {:ok, fun.()}
  rescue
    e in Error ->
      {:error, e}

    e ->
      {:error,
       Error.new(reason_for(kind), "plugin raised #{inspect(e.__struct__)}",
         details: %{plugin: id, class: e.__struct__}
       )}
  catch
    :throw, _value ->
      {:error, Error.new(reason_for(kind), "plugin threw a value", details: %{plugin: id})}

    :exit, reason ->
      {:error,
       Error.new(reason_for(kind), "plugin exited (#{exit_kind(reason)})", details: %{plugin: id})}
  end

  defp guard(caller, worker) do
    caller_mon = Process.monitor(caller)
    worker_mon = Process.monitor(worker)

    receive do
      {:DOWN, ^caller_mon, :process, _, _} -> Process.exit(worker, :kill)
      {:DOWN, ^worker_mon, :process, _, _} -> :ok
    end
  end

  defp flush(ref) do
    receive do
      {^ref, _} -> :ok
    after
      0 -> :ok
    end
  end

  # Only the shape of the exit reason; never its payload.
  defp exit_kind(reason) when is_atom(reason), do: Atom.to_string(reason)
  defp exit_kind({reason, _}) when is_atom(reason), do: Atom.to_string(reason)
  defp exit_kind(_), do: "abnormal"

  defp reason_for(:analyzer), do: :analyzer_error
  defp reason_for(_), do: :extractor_error
end
