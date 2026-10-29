defmodule Whiff.Test.TradeWhiffer do
  @moduledoc false
  @behaviour Whiff.Extractor

  @impl true
  def id, do: "test.trade"

  @impl true
  def version, do: 1

  @impl true
  def supports?(%Whiff.Input{extension: ".trade"}, _native), do: true
  def supports?(_, _), do: false

  @impl true
  def extract(%Whiff.Input{} = input, _native) do
    with {:ok, bytes} <- read_bounded(input, 64 * 1024),
         {:ok, trade} <- parse(bytes) do
      {:ok,
       %{
         "content" => %{"title" => "Trade #{trade.id}"},
         "format" => %{
           "test.trade" => %{
             "trade_id" => trade.id,
             "currency" => trade.currency,
             "qty" => trade.qty,
             "price" => trade.price
           }
         }
       }}
    else
      {:error, reason} ->
        {:error,
         Whiff.Error.new(:extractor_error, "trade extraction failed",
           details: %{cause: inspect(reason)}
         )}
    end
  end

  defp read_bounded(%{source: :path, path: path}, max) do
    case File.stat(path) do
      {:ok, %{size: size}} when size > max ->
        {:error, :too_large}

      {:ok, _} ->
        File.read(path)

      err ->
        err
    end
  end

  defp read_bounded(%{source: :binary, bytes: bytes}, max) when is_binary(bytes) do
    if byte_size(bytes) > max, do: {:error, :too_large}, else: {:ok, bytes}
  end

  defp parse(bytes) when is_binary(bytes) do
    case String.split(bytes, "\n", trim: true) do
      ["TRADE/1" | rest] -> {:ok, trade_from_fields(parse_fields(rest))}
      _ -> {:error, :bad_magic}
    end
  end

  defp parse_fields(lines) do
    Map.new(lines, &parse_field_line/1)
  end

  defp parse_field_line(line) do
    case String.split(line, "=", parts: 2) do
      [k, v] -> {k, v}
      [k] -> {k, ""}
    end
  end

  defp trade_from_fields(fields) do
    %{
      id: fields["id"] || "unknown",
      currency: fields["currency"] || "XXX",
      qty: fields["qty"] || "0",
      price: fields["price"] || "0"
    }
  end
end
