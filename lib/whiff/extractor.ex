defmodule Whiff.Extractor do
  @moduledoc """
  Behaviour for Elixir extractors ("Whiffers").

  An extractor adds fields to a native `whiff/1` report, typically for a
  proprietary format or for domain metadata. Callbacks run in isolated BEAM
  processes after native extraction, never inside the NIF.

  ## Lifecycle

  For each extractor, in list order:

  1. `c:id/0` and `c:version/0` are read (1 s limit).
  2. `c:supports?/2` decides whether to run. Decide from `Whiff.Input`
     descriptors (`:extension`, `:filename`, `:size`, `:mime`) or a small
     header read. Do not read the whole file here.
  3. `c:extract/2` returns a patch, which is checked, privacy-scrubbed
     (`Whiff.Privacy`), and merged (`Whiff.Merge`) according to `:mode`.

  With `mode: :fallback` (the default) step 3 runs only when native
  extraction did not cover the file. Each callback is limited by
  `:plugin_timeout_ms`. Raises, throws, exits, timeouts, invalid patches, and
  merge conflicts are recorded in `diagnostics.extractors` with
  `"status" => "error"`, or returned as `{:error, %Whiff.Error{}}` when
  `strict: true`.

  ## Example

  Reads at most 64 KiB from either a path or an in-memory input:

      defmodule MyApp.TradeWhiffer do
        @behaviour Whiff.Extractor

        @max_bytes 64 * 1024

        @impl true
        def id, do: "myapp.trade"

        @impl true
        def version, do: 1

        @impl true
        def supports?(%Whiff.Input{extension: ".trade", size: size}, _native),
          do: is_integer(size) and size <= @max_bytes

        def supports?(_input, _native), do: false

        @impl true
        def extract(%Whiff.Input{} = input, _native) do
          with {:ok, body} <- read(input),
               ["TRADE/1", "id=" <> id | _] <- String.split(body, ["\\r\\n", "\\n"]) do
            {:ok,
             %{
               "content" => %{"title" => "Trade " <> id},
               "format" => %{"myapp.trade" => %{"trade_id" => id}}
             }}
          else
            _ -> {:error, Whiff.Error.new(:extractor_error, "not a TRADE/1 file")}
          end
        end

        defp read(%Whiff.Input{source: :binary, bytes: bytes}), do: {:ok, bytes}

        defp read(%Whiff.Input{source: :path, path: path}) do
          with {:ok, io} <- File.open(path, [:read, :binary]) do
            try do
              case IO.binread(io, @max_bytes) do
                data when is_binary(data) -> {:ok, data}
                other -> {:error, other}
              end
            after
              File.close(io)
            end
          end
        end
      end

  Register per call with `extractors: [MyApp.TradeWhiffer]` or in config
  with `config :whiff, extractors: [MyApp.TradeWhiffer]`. A per-call list
  replaces the config list.
  """

  @typedoc """
  Report passed to the callbacks: the native report, plus patches from
  extractors that ran earlier in the same call. String keys only.

  ## Example

      %{
        "whiff" => %{"schema" => "whiff/1"},
        "identification" => %{"format" => "text", "extractor" => "text.plain", "detected_by" => "heuristic"},
        "diagnostics" => %{"extractors" => [%{"id" => "text.plain", "status" => "ok"}]}
      }
  """
  @type native_report :: %{optional(String.t()) => term()}

  @typedoc """
  Patch returned by `c:extract/2`. See `Whiff.Merge` for the section rules.

  ## Example

      %{
        "content" => %{"title" => "Trade T-1001", "keywords" => ["trade"]},
        "format" => %{"myapp.trade" => %{"trade_id" => "T-1001", "currency" => "USD"}}
      }
  """
  @type patch :: %{optional(String.t()) => term()}

  @doc """
  Stable id recorded in `diagnostics.extractors` and provenance.

  Must be a non-empty string of at most 128 bytes that does not equal a
  native extractor id. Use a namespace you own.

  ## Example

      def id, do: "myapp.trade"
  """
  @callback id() :: String.t()

  @doc """
  Version of this extractor's patch shape, recorded in
  `diagnostics.extractors`. An integer in `0..4_294_967_295`.

  ## Example

      def version, do: 1
  """
  @callback version() :: non_neg_integer()

  @doc """
  Whether `c:extract/2` should run for this input.

  ## Arguments

  * `input` — `t:Whiff.Input.t/0`
  * `native_report` — `t:native_report/0`

  ## Returns

  `true` to run. Any other value, including truthy values, skips the extractor.

  ## Examples

      def supports?(%Whiff.Input{extension: ".trade"}, _native), do: true
      def supports?(_input, _native), do: false

      # Run only when native detection found plain text.
      def supports?(_input, %{"identification" => %{"format" => "text"}}), do: true
  """
  @callback supports?(Whiff.Input.t(), native_report()) :: boolean()

  @doc """
  Produce a patch to merge into the report.

  ## Arguments

  * `input` — `t:Whiff.Input.t/0`. `:path` is set for `source: :path`;
    `:bytes` is set for `source: :binary`.
  * `native_report` — `t:native_report/0`

  ## Returns

  * `{:ok, patch}` — `t:patch/0`
  * `{:error, %Whiff.Error{}}` — recorded in diagnostics, or returned with
    `strict: true`. The message is privacy-scrubbed and truncated to 256
    bytes before it is stored.

  Any other return value is recorded as an `:extractor_error` that names only
  the value's shape.

  ## Examples

      {:ok, %{"format" => %{"myapp.trade" => %{"trade_id" => "T-1001"}}}}

      {:error, Whiff.Error.new(:extractor_error, "not a TRADE/1 file")}
  """
  @callback extract(Whiff.Input.t(), native_report()) ::
              {:ok, patch()} | {:error, Whiff.Error.t()}
end
