defmodule Whiff.Analyzer do
  @moduledoc """
  Behaviour for Elixir analyzers.

  Analyzers run after native extraction and after all `Whiff.Extractor`
  modules. Each receives the report built so far and returns a partial patch.
  Patches always merge in `:augment` mode: they add fields and append
  `content.keywords`, `security.risks`, and `diagnostics.warnings`, but never
  replace an existing value. A value set by an earlier plugin is a conflict.

  Analyzers run in isolated processes with the same timeout, privacy scrub,
  and failure handling as extractors (see `Whiff.Extractor`).

  ## Example

      defmodule MyApp.SensitivityAnalyzer do
        @behaviour Whiff.Analyzer

        @impl true
        def id, do: "myapp.sensitivity"

        @impl true
        def version, do: 1

        @impl true
        def analyze(report, _input) do
          secrets = map_size(get_in(report, ["security", "secrets"]) || %{})

          risks =
            if secrets > 0,
              do: [%{"kind" => "embedded_secret", "category" => "data_exposure", "severity" => "high"}],
              else: []

          {:ok,
           %{
             "metadata" => %{"myapp.sensitivity" => %{"secret_kinds" => secrets}},
             "security" => %{"risks" => risks}
           }}
        end
      end

  Register per call with `analyzers: [MyApp.SensitivityAnalyzer]` or in
  config with `config :whiff, analyzers: [...]`. A per-call list replaces the
  config list.
  """

  @typedoc """
  Report passed to `c:analyze/2`: the native report plus all extractor
  patches. String keys only.

  ## Example

      %{"content" => %{"title" => "Trade T-1001"}, "format" => %{"myapp.trade" => %{"trade_id" => "T-1001"}}}
  """
  @type report :: %{optional(String.t()) => term()}

  @doc """
  Stable id recorded in `diagnostics.extractors` and provenance. Same rules
  as `c:Whiff.Extractor.id/0`.

  ## Example

      def id, do: "myapp.sensitivity"
  """
  @callback id() :: String.t()

  @doc """
  Version of this analyzer's patch shape, an integer in `0..4_294_967_295`.

  ## Example

      def version, do: 1
  """
  @callback version() :: non_neg_integer()

  @doc """
  Analyze the report and return a patch.

  ## Arguments

  * `report` — `t:report/0`
  * `input` — `t:Whiff.Input.t/0` for the same call

  ## Returns

  * `{:ok, patch}` — string-keyed patch (see `Whiff.Merge`)
  * `{:error, %Whiff.Error{}}` — recorded in diagnostics, or returned with
    `strict: true`

  Raising, throwing, exiting, or exceeding `:plugin_timeout_ms` is recorded
  as an `:analyzer_error` or `:timeout`.

  ## Examples

      {:ok, %{"metadata" => %{"myapp.sensitivity" => %{"secret_kinds" => 0}}}}

      {:error, Whiff.Error.new(:analyzer_error, "classifier unavailable")}
  """
  @callback analyze(report(), Whiff.Input.t()) :: {:ok, map()} | {:error, Whiff.Error.t()}
end
