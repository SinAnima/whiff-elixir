defmodule Whiff.Native do
  @moduledoc false

  mix_config = Mix.Project.config()
  version = mix_config[:version]
  github_url = "https://github.com/SinAnima/whiff-elixir"

  # Force a source build until a release checksum exists (Hex consumers use
  # precompiled artifacts). Also force for local Mix envs that need the NIF.
  checksum_path = Path.expand("../../checksum-Elixir.Whiff.Native.exs", __DIR__)

  use RustlerPrecompiled,
    otp_app: :whiff,
    crate: "whiff_native",
    base_url: "#{github_url}/releases/download/v#{version}",
    version: version,
    targets: [
      "aarch64-apple-darwin",
      "x86_64-apple-darwin",
      "x86_64-unknown-linux-gnu",
      "aarch64-unknown-linux-gnu",
      "x86_64-pc-windows-msvc"
    ],
    force_build:
      System.get_env("WHIFF_BUILD") in ["1", "true"] or
        System.get_env("RUSTLER_PRECOMPILED_FORCE_BUILD") in ["1", "true"] or
        Mix.env() in [:dev, :test, :docs] or
        not File.exists?(checksum_path)

  @doc false
  def extract_path(_path, _options_json), do: :erlang.nif_error(:nif_not_loaded)

  @doc false
  def extract_bytes(_data, _name, _options_json), do: :erlang.nif_error(:nif_not_loaded)

  @doc false
  def llm_path(_path, _options_json), do: :erlang.nif_error(:nif_not_loaded)

  @doc false
  def native_version, do: :erlang.nif_error(:nif_not_loaded)
end
