defmodule Whiff.Error do
  @moduledoc """
  Exception and error struct returned by `Whiff` public APIs.

  Bang variants raise this same struct. Non-bang variants return
  `{:error, %Whiff.Error{}}`.
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
  Build an error from a reason atom and message.
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
