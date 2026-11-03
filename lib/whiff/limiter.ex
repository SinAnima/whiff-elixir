defmodule Whiff.Limiter do
  @moduledoc """
  Process-shared semaphore bounding concurrent native (NIF) work.

  Slots live in the `:whiff_native_limiter` ETS table (`:current` / `:max`).
  After waiting longer than the wait budget (default 60s, overridable via the
  ETS key `:wait_ms` for tests), acquisition **fail-opens** as `:bypassed`:
  the function still runs, but the counter is not touched and `release/0` is
  not called — so a timeout never undercounts in-flight work.
  """

  @table :whiff_native_limiter
  @default_max 8
  @default_wait_ms 60_000
  @sleep_ms 10

  @doc """
  Run `fun` under the native concurrency semaphore.

  Returns whatever `fun` returns. Only decrements the counter when this call
  successfully acquired a slot.
  """
  @spec with_native((-> result)) :: result when result: var
  def with_native(fun) when is_function(fun, 0) do
    case acquire() do
      :acquired ->
        try do
          fun.()
        after
          release()
        end

      :bypassed ->
        fun.()
    end
  end

  defp acquire do
    max = get(:max, @default_max)
    wait_ms = get(:wait_ms, @default_wait_ms)
    wait_acquire(max, wait_ms, 0)
  end

  defp wait_acquire(_max, wait_ms, waited) when waited > wait_ms do
    # Fail open after the budget to avoid deadlock if the counter is stuck.
    # Bypass must not release — we never acquired a slot.
    :bypassed
  end

  defp wait_acquire(max, wait_ms, waited) do
    # Uncapped +1 then compare so saturation is detectable. The old
    # `{2, 1, max, max}` threshold form returned `max` when already full and
    # always looked like a successful acquire.
    case :ets.update_counter(@table, :current, 1, {:current, 0}) do
      n when n <= max ->
        :acquired

      _over ->
        :ets.update_counter(@table, :current, {2, -1, 0, 0})
        Process.sleep(@sleep_ms)
        wait_acquire(max, wait_ms, waited + @sleep_ms)
    end
  rescue
    ArgumentError ->
      # Table missing (e.g. tests without application) — proceed without accounting.
      :bypassed
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
