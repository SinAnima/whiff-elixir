defmodule Whiff.LimiterTest do
  use ExUnit.Case, async: false

  @table :whiff_native_limiter

  setup do
    ensure_table()
    previous = snapshot()

    on_exit(fn ->
      ensure_table()
      restore(previous)
    end)

    :ok
  end

  test "acquire and release restore :current" do
    :ets.insert(@table, {:current, 0})
    :ets.insert(@table, {:max, 8})

    assert Whiff.Limiter.with_native(fn ->
             assert current() == 1
             :ok
           end) == :ok

    assert current() == 0
  end

  test "fail-open bypass does not undercount :current" do
    # Saturate: max 1, hold the only slot in another process.
    :ets.insert(@table, {:max, 1})
    :ets.insert(@table, {:current, 0})
    :ets.insert(@table, {:wait_ms, 30})

    parent = self()

    holder =
      Task.async(fn ->
        Whiff.Limiter.with_native(fn ->
          send(parent, :held)
          receive do
            :release -> :ok
          after
            5_000 -> :timeout
          end
        end)
      end)

    assert_receive :held, 1_000
    assert current() == 1
    baseline = current()

    assert Whiff.Limiter.with_native(fn -> :bypassed_ran end) == :bypassed_ran

    # Bypass must not decrement — counter stays at the holder's 1.
    assert current() == baseline

    send(holder.pid, :release)
    assert Task.await(holder) == :ok
    assert current() == 0
  end

  defp ensure_table do
    case :ets.whereis(@table) do
      :undefined ->
        :ets.new(@table, [
          :named_table,
          :public,
          :set,
          read_concurrency: true,
          write_concurrency: true
        ])

        :ets.insert(@table, {:max, 8})
        :ets.insert(@table, {:current, 0})
        :ets.insert(@table, {:wait_ms, 60_000})

      _ ->
        :ok
    end
  end

  defp current do
    case :ets.lookup(@table, :current) do
      [{:current, n}] -> n
      _ -> 0
    end
  end

  defp snapshot do
    %{
      max: lookup(:max, 8),
      current: lookup(:current, 0),
      wait_ms: lookup(:wait_ms, 60_000)
    }
  end

  defp restore(%{max: max, current: current, wait_ms: wait_ms}) do
    :ets.insert(@table, {:max, max})
    :ets.insert(@table, {:current, current})
    :ets.insert(@table, {:wait_ms, wait_ms})
  end

  defp lookup(key, default) do
    case :ets.lookup(@table, key) do
      [{^key, value}] -> value
      _ -> default
    end
  end
end
