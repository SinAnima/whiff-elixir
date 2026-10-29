defmodule Whiff.Error do
  @moduledoc """
  Error and exception type for all public `Whiff` APIs.

  Non-bang functions return `{:error, %Whiff.Error{}}`. Bang functions
  (`extract!/2`, `extract_binary!/2`, `llm!/2`) raise this same struct.

  ## Fields

  * `:reason` — stable atom classifying the failure (see `t:reason/0`)
  * `:message` — human-readable description (no file contents or secrets)
  * `:path` — filesystem path or logical name when relevant; otherwise `nil`
  * `:details` — optional metadata map; keys `:bytes`, `:content`, and `:binary`
    (atom or string) are stripped so payloads are not retained

  ## Example

      iex> err = Whiff.Error.new(:enoent, "no such file", path: "missing.pdf")
      iex> err.reason
      :enoent
      iex> err.path
      "missing.pdf"
      iex> Exception.message(err)
      "enoent: no such file (path: missing.pdf)"
  """

  @typedoc """
  Stable failure classification.

  Common values:

  * `:enoent` — path not found
  * `:eacces` — permission denied inspecting the path
  * `:invalid_option` — unknown or invalid option
  * `:unsupported_input` — wrong argument type (non-binary path/bytes, etc.)
  * `:native_error` — other native/IO failure
  * `:extractor_error` / `:analyzer_error` — Elixir plugin failure (strict mode)
  * `:invalid_report` — report/patch failed validation or JSON decode
  * `:timeout` — plugin task exceeded `plugin_timeout_ms`
  * `:conflict` — merge collision (namespaced keys / protected fields)
  """
  @type reason ::
          :enoent
          | :eacces
          | :invalid_option
          | :unsupported_input
          | :native_error
          | :extractor_error
          | :analyzer_error
          | :invalid_report
          | :timeout
          | :conflict
          | atom()

  @typedoc """
  Public error struct. See the module doc for field meanings.
  """
  @type t :: %__MODULE__{
          message: String.t(),
          reason: reason(),
          path: String.t() | nil,
          details: map()
        }

  defexception [:message, :reason, :path, details: %{}]

  @impl true
  def message(%__MODULE__{message: message, reason: reason, path: path}) do
    base = "#{reason}: #{message}"

    if path do
      "#{base} (path: #{path})"
    else
      base
    end
  end

  @doc """
  Builds a `%Whiff.Error{}`.

  ## Arguments

  * `reason` — `t:reason/0` atom
  * `message` — short UTF-8 description
  * `opts` — optional keywords:
    * `:path` — `String.t()` associated path or name
    * `:details` — `map()` of extra context (sensitive keys scrubbed)

  ## Examples

      iex> Whiff.Error.new(:invalid_option, "unknown option(s): [:nope]").reason
      :invalid_option

      iex> err = Whiff.Error.new(:extractor_error, "parse failed", details: %{cause: ":bad_magic", bytes: <<1, 2>>})
      iex> err.details
      %{cause: ":bad_magic"}
  """
  @spec new(reason(), String.t(), keyword()) :: t()
  def new(reason, message, opts \\ []) when is_atom(reason) and is_binary(message) do
    %__MODULE__{
      reason: reason,
      message: message,
      path: Keyword.get(opts, :path),
      details: Keyword.get(opts, :details, %{}) |> scrub_details()
    }
  end

  defp scrub_details(details) when is_map(details) do
    Map.drop(details, [:bytes, "bytes", :content, "content", :binary, "binary"])
  end

  defp scrub_details(_), do: %{}
end
