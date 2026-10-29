defmodule Whiff.Privacy do
  @moduledoc """
  Elixir-side privacy policy for **plugin patches**.

  Upstream Whiff's privacy analyzer does **not** automatically run on data added
  later by Elixir extractors/analyzers. This module applies a conservative
  redaction pass when `privacy: :strict` (default). It is **not** claimed to be
  equivalent to upstream redaction.
  """

  @email ~r/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/
  @phone ~r/\b(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}\b/
  @secretish ~r/(?i)(api[_-]?key|secret|password|token|bearer)\s*[:=]\s*\S+/

  @doc """
  Apply privacy policy to a plugin patch map.
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
