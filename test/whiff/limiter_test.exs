defmodule Whiff.LimiterTest do
  use ExUnit.Case, async: true

  alias Whiff.Limiter

  setup context do
    name = :"limiter_#{System.unique_integer([:positive])}"

    start_supervised!(
      {Limiter, name: name, max: context[:max] || 1, wait_ms: context[:wait_ms] || 1_000}
    )

    %{server: name}
  end

  defp hold(server) do
    parent = self()

    pid =
      spawn(fn ->
        Limiter.with_native(
          fn ->
            send(parent, {:held, self()})

            receive do
              :release -> :ok
            end
          end,
          server: server
        )
      end)

    assert_receive {:held, ^pid}
    pid
  end

  test "acquire and release return the slot", %{server: server} do
    assert Limiter.with_native(fn -> Limiter.stats(server).current end, server: server) == 1
    assert Limiter.stats(server).current == 0
  end

  test "a raising function still releases its slot", %{server: server} do
    assert_raise RuntimeError, fn -> Limiter.with_native(fn -> raise "x" end, server: server) end
    assert Limiter.stats(server).current == 0
  end

  test "a killed holder frees its slot", %{server: server} do
    holder = hold(server)
    assert Limiter.stats(server).current == 1

    Process.exit(holder, :kill)
    assert Limiter.with_native(fn -> :ran end, server: server) == :ran
    assert Limiter.stats(server).current == 0
  end

  @tag wait_ms: 50
  test "waiting past wait_ms returns :overloaded and never bypasses", %{server: server} do
    holder = hold(server)

    assert {:error, %Whiff.Error{reason: :overloaded}} =
             Limiter.with_native(fn -> flunk("must not run") end, server: server)

    assert Limiter.stats(server) == %{current: 1, max: 1, waiting: 0, wait_ms: 50}
    send(holder, :release)
  end

  test "waiters are served in FIFO order", %{server: server} do
    holder = hold(server)
    parent = self()

    for i <- 1..3 do
      spawn(fn -> Limiter.with_native(fn -> send(parent, {:ran, i}) end, server: server) end)
      wait_until(fn -> Limiter.stats(server).waiting == i end)
    end

    send(holder, :release)
    assert_receive {:ran, first}
    assert_receive {:ran, second}
    assert_receive {:ran, third}
    assert [first, second, third] == [1, 2, 3]
    wait_until(fn -> Limiter.stats(server).current == 0 end)
  end

  test "a killed waiter leaves the queue", %{server: server} do
    holder = hold(server)
    waiter = spawn(fn -> Limiter.with_native(fn -> :never end, server: server) end)
    wait_until(fn -> Limiter.stats(server).waiting == 1 end)

    Process.exit(waiter, :kill)
    wait_until(fn -> Limiter.stats(server).waiting == 0 end)

    send(holder, :release)
    wait_until(fn -> Limiter.stats(server).current == 0 end)
  end

  test "runs without a slot when the limiter is not running" do
    assert Limiter.with_native(fn -> :ran end, server: :no_such_limiter) == :ran
  end

  defp wait_until(fun, attempts \\ 100) do
    cond do
      fun.() ->
        :ok

      attempts == 0 ->
        flunk("condition not met")

      true ->
        Process.sleep(5)
        wait_until(fun, attempts - 1)
    end
  end
end
