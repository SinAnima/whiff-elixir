defmodule Whiff.Extractor do
  @moduledoc """
  Behaviour for Elixir-written extractors ("Whiffers").

  Callbacks run in BEAM processes **outside** the NIF — never as Rust plugin
  callbacks. Prefer `supports?/2` using `Whiff.Input` descriptors (and optional
  limited header probes) rather than loading entire large files.
  """

  @type native_report :: map()

  @callback id() :: String.t()
  @callback version() :: pos_integer()
  @callback supports?(Whiff.Input.t(), native_report()) :: boolean()
  @callback extract(Whiff.Input.t(), native_report()) ::
              {:ok, map()} | {:error, Whiff.Error.t()}

  @optional_callbacks []
end
