defmodule Whiff.Privacy do
  @moduledoc """
  Redaction for **Elixir plugin patches** and plugin error messages.

  Upstream Whiff's privacy analyzer does not re-scan data added by Elixir
  extractors or analyzers. With `privacy: :strict` (the default), each plugin
  patch passes through `scrub_patch/2` before it is merged.

  The patterns, validity checks, and `[redacted:<kind>]` markers are ported
  from upstream `whiff` 0.8.0 (`src/text/sensitive.rs`), so a value redacted
  natively and a value redacted here look the same. One deviation: a private
  key is redacted from its `BEGIN` line through its `END` line, where
  upstream replaces only the `BEGIN` line.

  ## Kinds

  Secrets (applied first): `private_key`, `aws_access_key_id`, `github_token`,
  `slack_token`, `google_api_key`, `stripe_secret_key`, `anthropic_api_key`,
  `openai_api_key`, `jwt`, `url_credentials`, `credential_assignment`
  (for example `password=hunter22`, skipped for placeholders such as
  `${VAR}` or `changeme`).

  Personal data: `email`, `phone` (international `+44 20 7946 0958` or
  bracketed area code `(555) 123-4567`), `iban` (mod-97 checked),
  `payment_card` (Luhn checked, 13–19 digits).

  Map keys are checked too. A patch with a key that matches any pattern is
  rejected with `:invalid_report`, because redacting keys could merge two keys
  into one. Numbers, booleans, and `nil` are not changed.

  ## Known limits

  * Phone numbers without `+` or a bracketed area code (`555-123-4567`) are
    not detected, matching upstream.
  * A 13–19 digit identifier that passes the Luhn check is redacted.
  * Names, postal addresses, and national ids are not detected.
  """

  @patterns [
    {"private_key",
     ~r/-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----(?:.*?-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----)?/s,
     :always},
    {"aws_access_key_id", ~r/\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/, :always},
    {"github_token", ~r/\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b/, :always},
    {"slack_token", ~r/\bxox[abposr]-[A-Za-z0-9-]{10,}/, :always},
    {"google_api_key", ~r/\bAIza[0-9A-Za-z_-]{35}\b/, :always},
    {"stripe_secret_key", ~r/\b[rs]k_live_[0-9A-Za-z]{20,}/, :always},
    {"anthropic_api_key", ~r/\bsk-ant-[A-Za-z0-9_-]{20,}/, :always},
    {"openai_api_key", ~r/\bsk-(?:proj-)?[A-Za-z0-9_-]{40,}/, :always},
    {"jwt", ~r/\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/, :always},
    {"url_credentials", ~r/\b[a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^\/\s:@]+:[^\/\s@]+@[^\s\/]+/, :always},
    {"credential_assignment",
     ~r/(?i)\b[\w.-]*?(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)["']?\s*[:=]\s*["']?[^\s"',;]{6,}/,
     :not_placeholder},
    {"email", ~r/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b/, :always},
    {"phone",
     ~r/(?:\+\d{1,3}[ .-]?(?:\(\d{1,4}\)|\d{1,4})|\(\d{2,4}\))[ .-]?\d{3,4}[ .-]?\d{3,4}\b/,
     :always},
    {"iban", ~r/\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){3,7}(?: ?[A-Z0-9]{1,3})?\b/, :iban},
    {"payment_card", ~r/\b(?:\d[ -]?){12,18}\d\b/, :luhn}
  ]

  @placeholders ~w(changeme xxxxxx password secret example redacted ******)

  @typedoc """
  Privacy mode.

  ## Example

      :strict
  """
  @type mode :: :strict | :off

  @doc """
  Apply the privacy policy to a plugin patch.

  ## Arguments

  * `patch` — string-keyed map produced by an extractor or analyzer
  * `mode` — `:strict` (redact) or `:off` (return unchanged)

  ## Returns

  * `{:ok, patch}` — possibly redacted
  * `{:error, %Whiff.Error{reason: :invalid_report}}` — a key matches a pattern
  * `{:error, %Whiff.Error{reason: :invalid_option}}` — `mode` is not `:strict` or `:off`

  ## Examples

      iex> Whiff.Privacy.scrub_patch(%{"content" => %{"excerpt" => "agent@example.com"}}, :off)
      {:ok, %{"content" => %{"excerpt" => "agent@example.com"}}}

      iex> {:ok, scrubbed} = Whiff.Privacy.scrub_patch(%{"content" => %{"excerpt" => "mail agent@example.com"}}, :strict)
      iex> scrubbed["content"]["excerpt"]
      "mail [redacted:email]"

      iex> Whiff.Privacy.scrub_patch(%{"n" => "order 20241231 qty 1000000"}, :strict)
      {:ok, %{"n" => "order 20241231 qty 1000000"}}

      iex> Whiff.Privacy.scrub_patch(%{"metadata" => %{"agent@example.com" => 1}}, :strict)
      {:error, %Whiff.Error{reason: :invalid_report, message: "plugin patch key matches a sensitive pattern", path: nil, details: %{}}}

      iex> Whiff.Privacy.scrub_patch(%{}, :maybe)
      {:error, %Whiff.Error{reason: :invalid_option, message: "privacy must be :strict or :off", path: nil, details: %{}}}
  """
  @spec scrub_patch(map(), mode()) :: {:ok, map()} | {:error, Whiff.Error.t()}
  def scrub_patch(patch, :off) when is_map(patch), do: {:ok, patch}

  def scrub_patch(patch, :strict) when is_map(patch) do
    if sensitive_key?(patch) do
      {:error, Whiff.Error.new(:invalid_report, "plugin patch key matches a sensitive pattern")}
    else
      {:ok, walk(patch)}
    end
  end

  def scrub_patch(_, _),
    do: {:error, Whiff.Error.new(:invalid_option, "privacy must be :strict or :off")}

  @doc """
  Redact one string under `mode`.

  ## Examples

      iex> Whiff.Privacy.scrub_string("call +44 20 7946 0958 or (555) 123-4567", :strict)
      "call [redacted:phone] or [redacted:phone]"

      iex> Whiff.Privacy.scrub_string("card 4111 1111 1111 1111", :strict)
      "card [redacted:payment_card]"

      iex> Whiff.Privacy.scrub_string("IBAN GB82 WEST 1234 5698 7654 32", :strict)
      "IBAN [redacted:iban]"

      iex> Whiff.Privacy.scrub_string("password=hunter22 token=${TOKEN}", :strict)
      "[redacted:credential_assignment] token=${TOKEN}"

      iex> Whiff.Privacy.scrub_string("password=hunter22", :off)
      "password=hunter22"
  """
  @spec scrub_string(String.t(), mode()) :: String.t()
  def scrub_string(string, :off) when is_binary(string), do: string

  def scrub_string(string, :strict) when is_binary(string) do
    Enum.reduce(@patterns, string, &redact/2)
  end

  defp redact({kind, regex, check}, string) do
    Regex.replace(regex, string, &if(valid?(check, &1), do: "[redacted:#{kind}]", else: &1))
  end

  defp walk(map) when is_map(map), do: Map.new(map, fn {k, v} -> {k, walk(v)} end)
  defp walk(list) when is_list(list), do: Enum.map(list, &walk/1)
  defp walk(bin) when is_binary(bin), do: scrub_string(bin, :strict)
  defp walk(other), do: other

  defp sensitive_key?(map) when is_map(map) do
    Enum.any?(map, fn {k, v} ->
      (is_binary(k) and scrub_string(k, :strict) != k) or sensitive_key?(v)
    end)
  end

  defp sensitive_key?(list) when is_list(list), do: Enum.any?(list, &sensitive_key?/1)
  defp sensitive_key?(_), do: false

  defp valid?(:always, _match), do: true
  defp valid?(:luhn, match), do: luhn?(match)
  defp valid?(:iban, match), do: iban?(match)
  defp valid?(:not_placeholder, match), do: not placeholder?(match)

  defp placeholder?(match) do
    value =
      match
      |> String.split(["=", ":"])
      |> List.last()
      |> String.trim(~s(" '))
      |> String.downcase()

    String.starts_with?(value, ["${", "<", "{{", "$", "%("]) or
      Enum.any?(@placeholders, &String.contains?(value, &1))
  end

  defp iban_digits(c) when c in ?A..?Z, do: Integer.digits(c - ?A + 10)
  defp iban_digits(c), do: [c - ?0]

  defp luhn?(match) do
    digits = for <<c <- match>>, c in ?0..?9, do: c - ?0

    length(digits) in 13..19 and Enum.uniq(digits) != [hd(digits)] and
      digits
      |> Enum.reverse()
      |> Enum.with_index()
      |> Enum.reduce(0, fn
        {d, i}, acc when rem(i, 2) == 1 -> acc + if(d * 2 > 9, do: d * 2 - 9, else: d * 2)
        {d, _}, acc -> acc + d
      end)
      |> rem(10) == 0
  end

  defp iban?(match) do
    compact = String.replace(match, ~r/\s/, "")

    if byte_size(compact) in 15..34 do
      <<head::binary-size(4), rest::binary>> = compact

      (rest <> head)
      |> String.to_charlist()
      |> Enum.flat_map(&iban_digits/1)
      |> Enum.reduce(0, fn d, acc -> rem(acc * 10 + d, 97) end) == 1
    else
      false
    end
  end
end
