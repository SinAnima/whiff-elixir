defmodule Whiff.Privacy do
  @moduledoc """
  Conservative redaction for **Elixir plugin patches** only.

  Upstream Whiff's privacy analyzer does not automatically re-scan data added
  later by Elixir extractors or analyzers. When `privacy: :strict` (the public
  API default), patches are scrubbed here before merge. This is not claimed to
  match upstream redaction.

  Patterns replaced under `:strict`:

  * email-like strings → `"[REDACTED_EMAIL]"`
  * phone-like strings → `"[REDACTED_PHONE]"`
  * `api_key` / `secret` / `password` / `token` / `bearer` assignments → `"[REDACTED]"`

  Non-string leaves (numbers, booleans, `nil`) are left unchanged.
  """

  @email ~r/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/
  @phone ~r/\b(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}\b/
  @secretish ~r/(?i)(api[_-]?key|secret|password|token|bearer)\s*[:=]\s*\S+/

  @doc """
  Apply privacy policy to a plugin patch map.

  ## Arguments

  * `patch` — string-keyed map produced by an extractor or analyzer
  * `mode` — `:strict` (redact) or `:off` (pass through)

  ## Returns

  * `{:ok, patch}` — possibly redacted map
  * `{:error, %Whiff.Error{reason: :invalid_option}}` — `mode` is not `:strict` or `:off`

  Does not raise.

  ## Examples

      iex> Whiff.Privacy.scrub_patch(%{"content" => %{"excerpt" => "agent@example.com"}}, :off)
      {:ok, %{"content" => %{"excerpt" => "agent@example.com"}}}

      iex> {:ok, scrubbed} = Whiff.Privacy.scrub_patch(%{"content" => %{"excerpt" => "mail agent@example.com"}}, :strict)
      iex> scrubbed["content"]["excerpt"]
      "mail [REDACTED_EMAIL]"

      iex> Whiff.Privacy.scrub_patch(%{}, :maybe)
      {:error, %Whiff.Error{reason: :invalid_option, message: "privacy must be :strict or :off", path: nil, details: %{}}}
  """
  @spec scrub_patch(map(), :strict | :off) :: {:ok, map()} | {:error, Whiff.Error.t()}
  def scrub_patch(patch, :off) when is_map(patch), do: {:ok, patch}

  def scrub_patch(patch, :strict) when is_map(patch) do
    {:ok, walk(patch)}
  end

  def scrub_patch(_, _),
    do: {:error, Whiff.Error.new(:invalid_option, "privacy must be :strict or :off")}

  defp walk(map) when is_map(map) do
    Map.new(map, fn {k, v} -> {k, walk(v)} end)
  end

  defp walk(list) when is_list(list), do: Enum.map(list, &walk/1)

  defp walk(bin) when is_binary(bin) do
    bin
    |> String.replace(@secretish, "[REDACTED]")
    |> String.replace(@email, "[REDACTED_EMAIL]")
    |> String.replace(@phone, "[REDACTED_PHONE]")
  end

  defp walk(other), do: other
end
