defmodule TradeWhiffer do
  @moduledoc """
  Example external Hex-style whiffer package for proprietary `.trade` files.
  """

  @behaviour Whiff.Extractor

  @impl true
  def id, do: "example.trade"

  @impl true
  def version, do: 1

  @impl true
  def supports?(%Whiff.Input{extension: ".trade"}, _native), do: true
  def supports?(_, _), do: false

  @impl true
  def extract(%Whiff.Input{path: path}, _native) when is_binary(path) do
    with {:ok, stat} <- File.stat(path),
         true <- stat.size <= 64 * 1024 || {:error, :too_large},
         {:ok, bytes} <- File.read(path),
         {:ok, trade} <- parse(bytes) do
      {:ok,
       %{
         "content" => %{"title" => "Trade #{trade.id}"},
         "format" => %{
           "example.trade" => %{
             "trade_id" => trade.id,
             "currency" => trade.currency
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

  def extract(%Whiff.Input{bytes: bytes}, _native) when is_binary(bytes) do
    case parse(bytes) do
      {:ok, trade} ->
        {:ok,
         %{
           "content" => %{"title" => "Trade #{trade.id}"},
           "format" => %{
             "example.trade" => %{"trade_id" => trade.id, "currency" => trade.currency}
           }
         }}

      {:error, reason} ->
        {:error,
         Whiff.Error.new(:extractor_error, "trade extraction failed",
           details: %{cause: inspect(reason)}
         )}
    end
  end

  defp parse(bytes) do
    case String.split(bytes, "\n", trim: true) do
      ["TRADE/1" | rest] ->
        fields =
          Map.new(rest, fn line ->
            case String.split(line, "=", parts: 2) do
              [k, v] -> {k, v}
              [k] -> {k, ""}
            end
          end)

        {:ok, %{id: fields["id"] || "unknown", currency: fields["currency"] || "XXX"}}

      _ ->
        {:error, :bad_magic}
    end
  end
end
