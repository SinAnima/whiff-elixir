defmodule Whiff.PrivacyTest do
  use ExUnit.Case, async: true

  doctest Whiff.Privacy

  alias Whiff.Privacy

  test "off leaves patch unchanged" do
    patch = %{"content" => %{"excerpt" => "agent@example.com"}}
    assert {:ok, ^patch} = Privacy.scrub_patch(patch, :off)
  end

  test "strict redacts nested maps, lists, and scalars" do
    patch = %{
      "content" => %{
        "excerpt" => "mail agent@example.com call +1-555-123-4567 password=hunter2",
        "keywords" => ["ok", "token=abc"],
        "n" => 1
      }
    }

    assert {:ok, scrubbed} = Privacy.scrub_patch(patch, :strict)
    excerpt = get_in(scrubbed, ["content", "excerpt"])
    refute excerpt =~ "agent@example.com"
    refute excerpt =~ "hunter2"
    assert excerpt =~ "REDACTED"
    assert get_in(scrubbed, ["content", "keywords"]) |> Enum.any?(&String.contains?(&1, "REDACTED"))
    assert get_in(scrubbed, ["content", "n"]) == 1
  end

  test "rejects invalid privacy mode" do
    assert {:error, %Whiff.Error{reason: :invalid_option}} =
             Privacy.scrub_patch(%{}, :maybe)
  end
end
