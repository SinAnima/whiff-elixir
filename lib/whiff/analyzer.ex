defmodule Whiff.Analyzer do
  @moduledoc """
  Behaviour for post-extraction Elixir analyzers.

  Analyzers return a **partial validated patch**, not a whole replacement report.
  They run after native extraction and Elixir whiffers.
  """

  @callback id() :: String.t()
  @callback version() :: pos_integer()
  @callback analyze(map(), Whiff.Input.t()) :: {:ok, map()} | {:error, Whiff.Error.t()}
end
