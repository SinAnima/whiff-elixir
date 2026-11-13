defmodule Whiff.PrivacyTest do
  use ExUnit.Case, async: true

  doctest Whiff.Privacy

  alias Whiff.Privacy

  defp scrub(text), do: Privacy.scrub_string(text, :strict)

  test "off leaves the patch unchanged" do
    patch = %{"content" => %{"excerpt" => "agent@example.com"}}
    assert {:ok, ^patch} = Privacy.scrub_patch(patch, :off)
  end

  test "strict redacts nested maps and lists and keeps non-strings" do
    patch = %{
      "content" => %{
        "excerpt" => "mail agent@example.com password=hunter22",
        "keywords" => ["ok", "token=abcdef123"],
        "n" => 1,
        "flag" => true,
        "none" => nil
      }
    }

    assert {:ok, scrubbed} = Privacy.scrub_patch(patch, :strict)

    assert scrubbed["content"] == %{
             "excerpt" => "mail [redacted:email] [redacted:credential_assignment]",
             "keywords" => ["ok", "[redacted:credential_assignment]"],
             "n" => 1,
             "flag" => true,
             "none" => nil
           }
  end

  test "secret kinds" do
    assert scrub("AKIAIOSFODNN7EXAMPLE") == "[redacted:aws_access_key_id]"
    assert scrub("ghp_" <> String.duplicate("a", 36)) == "[redacted:github_token]"
    assert scrub("xoxb-1234567890-abc") == "[redacted:slack_token]"
    assert scrub("sk-ant-" <> String.duplicate("a", 20)) == "[redacted:anthropic_api_key]"
    assert scrub("postgres://app:s3cretpw@db/prod") == "[redacted:url_credentials]/prod"

    assert scrub("x -----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY----- y") ==
             "x [redacted:private_key] y"
  end

  test "placeholders are not treated as credentials" do
    for text <- ["password=${DB_PASSWORD}", "token=<your-token>", "secret: changeme123"] do
      assert scrub(text) == text
    end
  end

  test "numbers that are not personal data are kept" do
    for text <- ["order 20241231", "qty 1000000", "2024-12-31", "555-123-4567", "1111111111111"] do
      assert scrub(text) == text
    end
  end

  test "validity checks reject look-alikes" do
    assert scrub("4111 1111 1111 1112") == "4111 1111 1111 1112"
    assert scrub("GB00 WEST 1234 5698 7654 32") == "GB00 WEST 1234 5698 7654 32"
  end

  test "rejects patches with sensitive keys at any depth" do
    assert {:error, %Whiff.Error{reason: :invalid_report}} =
             Privacy.scrub_patch(%{"metadata" => %{"x" => [%{"+44 20 7946 0958" => 1}]}}, :strict)

    assert {:ok, _} = Privacy.scrub_patch(%{"metadata" => %{"+44 20 7946 0958" => 1}}, :off)
  end

  test "rejects an invalid mode" do
    assert {:error, %Whiff.Error{reason: :invalid_option}} = Privacy.scrub_patch(%{}, :maybe)
  end
end
