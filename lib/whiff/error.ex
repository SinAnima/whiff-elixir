defmodule Whiff.Error do
  @moduledoc """
  Error and exception type for the public `Whiff` API.

  Non-bang functions return `{:error, %Whiff.Error{}}`. Bang functions
  (`Whiff.extract!/2`, `Whiff.extract_binary!/2`, `Whiff.llm!/2`) raise the same
  struct.

  ## Fields

  * `:reason` — `t:reason/0`, a stable atom for pattern matching
  * `:message` — short description. Messages built by this library never
    contain file contents or plugin output; native IO messages include the
    path
  * `:path` — the path or logical name the error refers to, or `nil`
  * `:details` — map of extra context. Keys `:bytes`, `:content`, and `:binary`
    (atom or string, at any depth) are removed so payloads are not retained

  `Exception.message/1` includes the full `:path`. Log `Path.basename(err.path)`
  instead when paths are sensitive.

  ## Example

      iex> err = Whiff.Error.new(:enoent, "no such file", path: "missing.pdf")
      iex> {err.reason, err.path}
      {:enoent, "missing.pdf"}
      iex> Exception.message(err)
      "enoent: no such file (path: missing.pdf)"
  """

  @typedoc """
  Stable failure classification.

  * `:enoent` — path not found
  * `:eacces` — permission denied
  * `:invalid_option` — unknown or invalid option, or policy refusal such as a
    file over `:scratch_max_bytes`
  * `:unsupported_input` — wrong argument type, empty path, or a path the
    platform cannot represent
  * `:native_error` — other native or IO failure, including a caught native panic
  * `:overloaded` — no native slot became free within `:native_wait_ms`
  * `:extractor_error` / `:analyzer_error` — Elixir plugin failure
  * `:invalid_report` — report or plugin patch failed validation or JSON decode
  * `:timeout` — plugin exceeded `:plugin_timeout_ms`, or a batch item exceeded
    `:timeout` in `Whiff.extract_many/2`
  * `:conflict` — merge collision (protected field, namespace, or another
    plugin's value)

  ## Example

      :enoent
  """
  @type reason ::
          :enoent
          | :eacces
          | :invalid_option
          | :unsupported_input
          | :native_error
          | :overloaded
          | :extractor_error
          | :analyzer_error
          | :invalid_report
          | :timeout
          | :conflict

  @typedoc """
  Public error struct.

  ## Example

      %Whiff.Error{
        reason: :invalid_option,
        message: "unknown option(s): [:nope]",
        path: nil,
        details: %{unknown: [:nope]}
      }
  """
  @type t :: %__MODULE__{
          message: String.t(),
          reason: reason(),
          path: String.t() | nil,
          details: map()
        }

  defexception [:message, :reason, :path, details: %{}]

  @sensitive_keys [:bytes, "bytes", :content, "content", :binary, "binary"]

  @doc """
  Builds the exception for `raise/2`.

  A binary becomes the message with reason `:native_error`. A keyword list
  accepts `:reason`, `:message`, `:path`, and `:details`.

  ## Examples

      iex> Whiff.Error.exception("boom").reason
      :native_error

      iex> err = Whiff.Error.exception(reason: :timeout, message: "slow")
      iex> {err.reason, err.message}
      {:timeout, "slow"}
  """
  @impl true
  def exception(message) when is_binary(message), do: new(:native_error, message)

  def exception(opts) when is_list(opts) do
    new(
      Keyword.get(opts, :reason, :native_error),
      Keyword.get(opts, :message, ""),
      Keyword.take(opts, [:path, :details])
    )
  end

  @doc """
  Formats the exception for `Exception.message/1`.

  ## Examples

      iex> Exception.message(Whiff.Error.new(:enoent, "gone", path: "/tmp/x"))
      "enoent: gone (path: /tmp/x)"

      iex> Exception.message(Whiff.Error.new(:native_error, "boom"))
      "native_error: boom"
  """
  @impl true
  def message(%__MODULE__{message: message, reason: reason, path: path}) do
    base = "#{reason || :native_error}: #{message}"
    if path, do: "#{base} (path: #{path})", else: base
  end

  @doc """
  Builds a `%Whiff.Error{}`.

  ## Arguments

  * `reason` — `t:reason/0`
  * `message` — short UTF-8 description
  * `opts`:
    * `:path` — related path or name (default `nil`)
    * `:details` — map of extra context (default `%{}`); payload keys are removed

  ## Examples

      iex> Whiff.Error.new(:invalid_option, "unknown option(s): [:nope]").reason
      :invalid_option

      iex> err = Whiff.Error.new(:extractor_error, "parse failed",
      ...>   details: %{cause: ":bad_magic", bytes: <<1, 2>>, nested: %{content: "x", ok: 1}})
      iex> err.details
      %{cause: ":bad_magic", nested: %{ok: 1}}
  """
  @spec new(reason(), String.t(), keyword()) :: t()
  def new(reason, message, opts \\ []) when is_atom(reason) and is_binary(message) do
    %__MODULE__{
      reason: reason,
      message: message,
      path: Keyword.get(opts, :path),
      details: opts |> Keyword.get(:details, %{}) |> scrub_details()
    }
  end

  defp scrub_details(%_{} = struct), do: struct

  defp scrub_details(details) when is_map(details) do
    details
    |> Map.drop(@sensitive_keys)
    |> Map.new(fn {k, v} -> {k, scrub_value(v)} end)
  end

  defp scrub_details(_), do: %{}

  defp scrub_value(%_{} = struct), do: struct
  defp scrub_value(map) when is_map(map), do: scrub_details(map)
  defp scrub_value(list) when is_list(list), do: Enum.map(list, &scrub_value/1)
  defp scrub_value(other), do: other
end
