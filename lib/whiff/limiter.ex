defmodule Whiff.Limiter do
  @moduledoc false

  @table :whiff_native_limiter
  @default_max 8

  @doc """
  Run `fun` under a process-local semaphore bounding concurrent native work.
  """
  @spec with_native((-> result)) :: result when result: var
  def with_native(fun) when is_function(fun, 0) do
    acquire()

    try do
      fun.()
    after
      release()
    end
  end

  defp acquire do
    max = get(:max, @default_max)
    wait_acquire(max, 0)
  end

  defp wait_acquire(_max, waited) when waited > 60_000 do
    # Fail open after a minute to avoid deadlock if counter is corrupted.
    :ok
  end

  defp wait_acquire(max, waited) do
    case :ets.update_counter(@table, :current, {2, 1, max, max}, {:current, 0}) do
      n when n <= max ->
        :ok

      _ ->
        :ets.update_counter(@table, :current, {2, -1, 0, 0})
        Process.sleep(10)
        wait_acquire(max, waited + 10)
    end
  rescue
    ArgumentError ->
      # Table missing (e.g. tests without application) — proceed.
      :ok
  end

  defp release do
    :ets.update_counter(@table, :current, {2, -1, 0, 0})
  rescue
    ArgumentError -> :ok
  end

  defp get(key, default) do
    case :ets.lookup(@table, key) do
      [{^key, value}] -> value
      _ -> default
    end
  rescue
    ArgumentError -> default
  end
end
