defmodule TradeWhiffer.MixProject do
  use Mix.Project

  def project do
    [
      app: :trade_whiffer,
      version: "0.1.0",
      elixir: "~> 1.18",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  def application do
    [extra_applications: [:logger]]
  end

  defp deps do
    [
      {:whiff, path: "../.."},
      # Path deps compile under Mix.env :dev/:test, which forces a NIF source build.
      {:rustler, "~> 0.38", optional: true}
    ]
  end
end
