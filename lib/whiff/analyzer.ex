defmodule Whiff.Analyzer do
  @moduledoc """
  Behaviour for post-extraction Elixir analyzers.

  Analyzers run after native extraction and Elixir extractors. They return a
  **partial patch** (not a full report replacement), merged with
  `Whiff.Merge` in `:augment` style unless overridden by pipeline options.

  ## Minimal implementation

      defmodule MyApp.TitleAnalyzer do
        @behaviour Whiff.Analyzer

        @impl true
        def id, do: "myapp.title"

        @impl true
        def version, do: 1

        @impl true
        def analyze(report, _input) do
          title = get_in(report, ["content", "title"]) || "untitled"

          {:ok,
           %{
             "metadata" => %{
               "myapp.title" => %{"normalized" => String.upcase(title)}
             }
           }}
        end
      end

  Register with `analyzers: [MyApp.TitleAnalyzer]` or
  `config :whiff, analyzers: [...]`.
  """

  @doc """
  Stable analyzer id used in diagnostics (for example `"myapp.title"`).
  """
  @callback id() :: String.t()

  @doc """
  Positive integer version of this analyzer's patch shape.
  """
  @callback version() :: pos_integer()

  @doc """
  Analyze the current report and return a merge patch.

  ## Arguments

  * `report` — string-keyed `whiff/1` map after native extract (+ extractors)
  * `input` — `t:Whiff.Input.t/0` for the same call

  ## Returns

  * `{:ok, patch}` — string-keyed patch to merge
  * `{:error, %Whiff.Error{}}` — failure; with `strict: true` this fails the
    whole extract, otherwise it is recorded in `diagnostics`

  Raising or exiting inside the callback is caught by the plugin runner and
  treated like an analyzer error (or hard failure when `strict: true`).
  """
  @callback analyze(map(), Whiff.Input.t()) :: {:ok, map()} | {:error, Whiff.Error.t()}
end
