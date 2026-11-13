defmodule Whiff.PluginRunTest do
  use ExUnit.Case, async: true

  alias Whiff.Plugin

  test "returns ok values" do
    assert {:ok, 42} = Plugin.run(fn -> 42 end, timeout: 500, id: "ok")
  end

  test "rescues Whiff.Error from the plugin" do
    err = Whiff.Error.new(:extractor_error, "boom")

    assert {:error, %Whiff.Error{reason: :extractor_error, message: "boom"}} =
             Plugin.run(fn -> raise err end, id: "raise-err")
  end

  test "wraps unexpected exceptions as extractor_error" do
    assert {:error, %Whiff.Error{reason: :extractor_error, details: %{plugin: "boom"}}} =
             Plugin.run(fn -> raise "nope" end, id: "boom")
  end

  test "wraps throws" do
    assert {:error, %Whiff.Error{reason: :extractor_error, message: message}} =
             Plugin.run(fn -> throw(:bye) end, id: "thrower")

    assert message =~ "threw"
  end

  test "wraps exits inside the plugin fun" do
    assert {:error, %Whiff.Error{reason: :extractor_error, message: message}} =
             Plugin.run(fn -> exit(:kaboom) end, id: "exiter")

    assert message =~ "exited"
  end

  test "analyzer kind uses analyzer_error" do
    assert {:error, %Whiff.Error{reason: :analyzer_error}} =
             Plugin.run(fn -> raise "x" end, kind: :analyzer, id: "a1")
  end

  test "timeout returns :timeout" do
    assert {:error, %Whiff.Error{reason: :timeout, details: %{plugin: "slow"}}} =
             Plugin.run(fn -> Process.sleep(500) end, timeout: 20, id: "slow")
  end
end
