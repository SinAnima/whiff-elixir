defmodule Whiff.MixProject do
  use Mix.Project

  @version "0.4.0"
  @source_url "https://github.com/SinAnima/whiff-elixir"

  def project do
    [
      app: :whiff,
      version: @version,
      elixir: "~> 1.18",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      package: package(),
      description: description(),
      docs: docs(),
      elixirc_paths: elixirc_paths(Mix.env()),
      aliases: aliases(),
      test_coverage: [tool: ExCoveralls],
      preferred_cli_env: [
        coveralls: :test,
        "coveralls.detail": :test,
        "coveralls.html": :test,
        "coveralls.json": :test,
        "coveralls.github": :test,
        credo: :test,
        doctor: :test
      ]
    ]
  end

  def application do
    [
      extra_applications: [:logger],
      mod: {Whiff.Application, []}
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp deps do
    [
      # Optional: only needed when force-building the NIF (dev/test / WHIFF_BUILD=1).
      {:rustler, "~> 0.38", optional: true},
      {:rustler_precompiled, "~> 0.10"},
      {:jason, "~> 1.4"},
      {:ex_json_schema, "~> 0.10", only: :test},
      {:excoveralls, "~> 0.18", only: :test},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:doctor, "~> 0.23", only: [:dev, :test], runtime: false},
      {:ex_doc, "~> 0.34", only: [:dev, :docs], runtime: false}
    ]
  end

  defp aliases do
    [
      ci: &ci/1
    ]
  end

  defp description do
    "Elixir wrapper around the Rust whiff crate: sniff any file into a whiff/1 report, with first-class Elixir extractors and analyzers."
  end

  defp package do
    [
      name: "whiff",
      licenses: ["MIT"],
      links: %{
        "GitHub" => @source_url,
        "Upstream whiff" => "https://github.com/baoulo/whiff"
      },
      files: ~w(
        lib
        native/whiff_native/.cargo
        native/whiff_native/src
        native/whiff_native/Cargo.toml
        native/whiff_native/Cargo.lock
        native/whiff_native/README.md
        priv/schemas
        checksum-*.exs
        mix.exs
        README.md
        CHANGELOG.md
        LICENSE
      )
    ]
  end

  defp docs do
    [
      main: "readme",
      source_url: @source_url,
      extras: [
        "README.md",
        "CHANGELOG.md",
        "docs/adr/0001-baseline.md",
        "docs/hex-publish-checklist.md"
      ],
      groups_for_extras: [
        Guides: ["docs/adr/0001-baseline.md", "docs/hex-publish-checklist.md"]
      ]
    ]
  end

  defp ci(_) do
    steps = [
      # ["precommit", :dev],
      {"compile --warnings-as-errors", :dev},
      {"format --check-formatted", :dev},
      {"credo --strict", :dev},
      {"doctor", :dev},
      # # {"sobelow --config", :dev},
      # {"dialyzer", :dev},
      # {"coveralls", :test},
      {"test --cover", :test},
      {"docs --warnings-as-errors", :dev}
    ]

    Enum.each(steps, fn {task, env} ->
      Mix.shell().info(IO.ANSI.format([:bright, "==> mix #{task}", :reset]))

      mix_executable =
        System.find_executable("mix") ||
          Mix.raise("Could not find `mix` executable on PATH")

      {_, exit_code} =
        System.cmd(mix_executable, String.split(task),
          env: [{"MIX_ENV", to_string(env)}],
          into: IO.stream(:stdio, :line),
          stderr_to_stdout: true
        )

      if exit_code != 0 do
        Mix.raise("mix #{task} failed (exit code #{exit_code})")
      end
    end)

    Mix.shell().info(IO.ANSI.format([:green, :bright, "\nAll verification checks passed!", :reset]))
  end
end
