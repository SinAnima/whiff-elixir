defmodule TradeWhiffer do
  @moduledoc """
  Example `Whiff.Extractor` for proprietary `.trade` text files.

  The package depends on `whiff` and registers per call, which shows that
  extractors do not need to be built into `whiff`:

      Whiff.extract("deal.trade", extractors: [TradeWhiffer])

  A `.trade` file is UTF-8 text: a `TRADE/1` header line followed by
  `key=value` lines. Files larger than 64 KiB are not read.
  """

  @behaviour Whiff.Extractor

  @max_bytes 64 * 1024

  @doc ~S'Stable extractor id: `"example.trade"`.'
  @impl true
  def id, do: "example.trade"

  @doc "Patch shape version."
  @impl true
  def version, do: 1

  @doc """
  `true` for `.trade` inputs of at most 64 KiB.

  ## Examples

      iex> TradeWhiffer.supports?(Whiff.Input.from_binary("TRADE/1\\n", name: "a.trade"), %{})
      true

      iex> TradeWhiffer.supports?(Whiff.Input.from_binary("x", name: "a.txt"), %{})
      false
  """
  @impl true
  def supports?(%Whiff.Input{extension: ".trade", size: size}, _native),
    do: is_integer(size) and size <= @max_bytes

  def supports?(_input, _native), do: false

  @doc """
  Parse a `TRADE/1` body into a `format["example.trade"]` patch.

  ## Examples

      iex> input = Whiff.Input.from_binary("TRADE/1\\nid=T-7\\ncurrency=EUR\\n", name: "a.trade")
      iex> TradeWhiffer.extract(input, %{})
      {:ok,
       %{
         "content" => %{"title" => "Trade T-7"},
         "format" => %{"example.trade" => %{"trade_id" => "T-7", "currency" => "EUR"}}
       }}

      iex> {:error, err} = TradeWhiffer.extract(Whiff.Input.from_binary("nope", name: "a.trade"), %{})
      iex> {err.reason, err.message}
      {:extractor_error, "not a TRADE/1 file"}
  """
  @impl true
  def extract(%Whiff.Input{} = input, _native) do
    with {:ok, bytes} <- read(input),
         {:ok, trade} <- parse(bytes) do
      {:ok,
       %{
         "content" => %{"title" => "Trade #{trade.id}"},
         "format" => %{"example.trade" => %{"trade_id" => trade.id, "currency" => trade.currency}}
       }}
    else
      {:error, :bad_magic} ->
        {:error, Whiff.Error.new(:extractor_error, "not a TRADE/1 file")}

      {:error, reason} ->
        {:error, Whiff.Error.new(:extractor_error, "cannot read trade file: #{inspect(reason)}")}
    end
  end

  defp read(%Whiff.Input{source: :binary, bytes: bytes}), do: {:ok, bytes}

  defp read(%Whiff.Input{source: :path, path: path}) do
    with {:ok, io} <- File.open(path, [:read, :binary]) do
      try do
        case IO.binread(io, @max_bytes) do
          data when is_binary(data) -> {:ok, data}
          :eof -> {:ok, ""}
          {:error, reason} -> {:error, reason}
        end
      after
        File.close(io)
      end
    end
  end

  defp parse(bytes) do
    case String.split(bytes, ["\r\n", "\n", "\r"], trim: true) do
      ["TRADE/1" | rest] ->
        fields = Map.new(rest, &field/1)
        {:ok, %{id: fields["id"] || "unknown", currency: fields["currency"] || "XXX"}}

      _ ->
        {:error, :bad_magic}
    end
  end

  defp field(line) do
    case String.split(line, "=", parts: 2) do
      [k, v] -> {String.trim(k), String.trim(v)}
      [k] -> {String.trim(k), ""}
    end
  end
end
