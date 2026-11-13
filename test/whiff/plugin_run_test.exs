defmodule Whiff.PluginRunTest do
  use ExUnit.Case, async: true

  alias Whiff.Plugin

  @secret "jane.doe@example.com"

  test "returns ok values" do
    assert {:ok, 42} = Plugin.run(fn -> 42 end, timeout: 500, id: "ok")
  end

  test "passes a raised Whiff.Error through" do
    err = Whiff.Error.new(:extractor_error, "boom")
    assert {:error, ^err} = Plugin.run(fn -> raise err end, id: "raise-err")
  end

  test "raise, throw, and exit become errors without the payload" do
    cases = [
      fn -> raise ArgumentError, @secret end,
      fn -> throw(@secret) end,
      fn -> exit({:shutdown, @secret}) end
    ]

    for fun <- cases do
      assert {:error, %Whiff.Error{reason: :extractor_error, message: message}} =
               Plugin.run(fun, id: "p")

      refute message =~ @secret
    end
  end

  test "analyzer kind uses :analyzer_error" do
    assert {:error, %Whiff.Error{reason: :analyzer_error, message: "plugin raised RuntimeError"}} =
             Plugin.run(fn -> raise "x" end, kind: :analyzer, id: "a1")
  end

  test "a plugin that kills itself does not kill the caller" do
    assert {:error,
            %Whiff.Error{reason: :extractor_error, message: "plugin process exited (killed)"}} =
             Plugin.run(fn -> Process.exit(self(), :kill) end, id: "killer")

    assert Process.alive?(self())
  end

  test "a crash in a process linked to the plugin does not kill the caller" do
    assert {:error, %Whiff.Error{reason: :extractor_error}} =
             Plugin.run(
               fn ->
                 spawn_link(fn -> exit(:boom) end)
                 Process.sleep(1_000)
               end,
               id: "linked"
             )
  end

  test "timeout kills the plugin and returns :timeout" do
    parent = self()

    assert {:error, %Whiff.Error{reason: :timeout, details: %{plugin: "slow"}}} =
             Plugin.run(
               fn ->
                 send(parent, {:worker, self()})
                 Process.sleep(5_000)
               end,
               timeout: 20,
               id: "slow"
             )

    assert_received {:worker, worker}
    refute Process.alive?(worker)
  end

  test "the plugin is killed when its caller dies" do
    parent = self()

    caller =
      spawn(fn ->
        Plugin.run(
          fn ->
            send(parent, {:worker, self()})
            Process.sleep(5_000)
          end,
          timeout: 10_000
        )
      end)

    assert_receive {:worker, worker}
    ref = Process.monitor(worker)
    Process.exit(caller, :kill)
    assert_receive {:DOWN, ^ref, :process, ^worker, :killed}, 1_000
  end
end
