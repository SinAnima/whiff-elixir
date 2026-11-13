defmodule Whiff.Extractor do
  @moduledoc """
  Behaviour for Elixir extractors ("Whiffers").

  Callbacks run in BEAM processes outside the NIF. Use them for proprietary
  formats, domain fields, or cases where native coverage is incomplete.

  Prefer deciding `supports?/2` from `Whiff.Input` descriptors (`:extension`,
  `:filename`, `:size`, `:mime`) or a small header read. Avoid loading entire
  large files into memory unless required.

  Patches returned by `extract/2` are **string-keyed** maps merged into the
  native report by `Whiff.Merge` according to `:mode`
  (`:fallback` | `:augment` | `:override`).

  ## Minimal implementation

      defmodule MyApp.TradeWhiffer do
        @behaviour Whiff.Extractor

        @impl true
        def id, do: "myapp.trade"

        @impl true
        def version, do: 1

        @impl true
        def supports?(%Whiff.Input{extension: ".trade"}, _native), do: true
        def supports?(_input, _native), do: false

        @impl true
        def extract(%Whiff.Input{} = input, _native) do
          with {:ok, body} <- File.read(input.path) do
            {:ok,
             %{
               "content" => %{"title" => "Trade"},
               "format" => %{"myapp.trade" => %{"raw_size" => byte_size(body)}}
             }}
          else
            {:error, reason} ->
              {:error,
               Whiff.Error.new(:extractor_error, "read failed",
                 details: %{cause: inspect(reason)}
               )}
          end
        end
      end

  Register at call time with `extractors: [MyApp.TradeWhiffer]` or via
  `config :whiff, extractors: [...]`.
  """

  @typedoc """
  Native `whiff/1` report as a string-keyed map (from the NIF / Jason).

  ## Example

      %{"whiff" => %{"schema" => "whiff/1"}, "identification" => %{"format" => "pdf"}}
  """
  @type native_report :: %{optional(String.t()) => term()}

  @doc """
  Stable extractor id used in diagnostics and provenance (for example `"myapp.trade"`).
  """
  @callback id() :: String.t()

  @doc """
  Positive integer version of this extractor's patch shape.
  """
  @callback version() :: pos_integer()

  @doc """
  Return whether this extractor should run for `input` given the current native report.

  ## Arguments

  * `input` — `t:Whiff.Input.t/0` built by the public API
  * `native_report` — string-keyed report already produced by the NIF

  ## Returns

  `true` to invoke `c:extract/2`, otherwise `false`.
  """
  @callback supports?(Whiff.Input.t(), native_report()) :: boolean()

  @doc """
  Produce a patch map to merge into the native report.

  ## Arguments

  * `input` — `t:Whiff.Input.t/0` (may include `:path` or `:bytes`)
  * `native_report` — current string-keyed report

  ## Returns

  * `{:ok, patch}` — string-keyed map (typically under `"content"`, `"format"`, `"metadata"`)
  * `{:error, %Whiff.Error{}}` — failure; with `strict: true` this fails the whole extract,
    otherwise it is recorded in `diagnostics`

  Do not return atoms as map keys. Do not patch `"embedded"`. Prefer namespaced
  keys under `"format"` / `"metadata"` (for example `"format" => %{"myapp.trade" => %{...}}`).
  """
  @callback extract(Whiff.Input.t(), native_report()) ::
              {:ok, map()} | {:error, Whiff.Error.t()}

  @optional_callbacks []
end
