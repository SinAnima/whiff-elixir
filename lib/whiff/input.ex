defmodule Whiff.Input do
  @moduledoc """
  Canonical description of one extraction input for Elixir plugins.

  Built by the public API before native extraction and passed to
  `Whiff.Extractor` / `Whiff.Analyzer` callbacks. Prefer deciding
  `supports?/2` from descriptors (`:extension`, `:filename`, `:size`) instead
  of reading entire large files.

  ## Fields

  * `:source` — `:path` or `:binary`
  * `:path` — absolute or relative filesystem path when `source: :path`
  * `:bytes` — payload when `source: :binary` (may be large; do not log it)
  * `:filename` — basename used for detection and `supports?/2`
  * `:extension` — lowercase extension including the dot (e.g. `".pdf"`), or `nil`
  * `:mime` — optional caller-supplied MIME type
  * `:size` — byte size when known

  ## Examples

      iex> input = Whiff.Input.from_path("/tmp/report.pdf")
      iex> input.source
      :path
      iex> input.filename
      "report.pdf"
      iex> input.extension
      ".pdf"

      iex> {:ok, input} = ok_binary()
      iex> input.source
      :binary
      iex> input.extension
      ".trade"
      iex> Map.has_key?(Whiff.Input.present(input), :bytes)
      false

  The helper below is only for doctests:

      iex> false
      false
  """

  # Keep doctest helper tiny and local via a private-looking example in from_binary docs.

  @enforce_keys [:source]
  defstruct source: nil,
            path: nil,
            bytes: nil,
            filename: nil,
            extension: nil,
            mime: nil,
            size: nil

  @typedoc "Whether the payload is on disk or already in memory."
  @type source :: :path | :binary

  @typedoc """
  Input struct passed to Elixir plugins. See the module doc for fields.
  """
  @type t :: %__MODULE__{
          source: source(),
          path: String.t() | nil,
          bytes: binary() | nil,
          filename: String.t() | nil,
          extension: String.t() | nil,
          mime: String.t() | nil,
          size: non_neg_integer() | nil
        }

  @doc """
  Builds input from a filesystem path.

  Does not read file contents. `:size` is filled from `File.stat/1` when the
  path exists; otherwise `nil`.

  ## Arguments

  * `path` — UTF-8 path string

  ## Examples

      iex> i = Whiff.Input.from_path("docs/notes.TXT")
      iex> {i.source, i.filename, i.extension}
      {:path, "notes.TXT", ".txt"}
  """
  @spec from_path(Path.t()) :: t()
  def from_path(path) when is_binary(path) do
    filename = Path.basename(path)
    ext = extension_of(filename)

    %__MODULE__{
      source: :path,
      path: path,
      filename: filename,
      extension: ext,
      size: safe_size(path)
    }
  end

  @doc """
  Builds input from in-memory bytes.

  ## Arguments

  * `bytes` — binary payload
  * `opts` — optional keywords:
    * `:name` / `:filename` — basename for detection (default `"input.bin"`)
    * `:mime` — optional MIME string

  ## Returns

  * `%Whiff.Input{}` on success
  * `{:error, %Whiff.Error{reason: :invalid_option}}` if `:name` is present but not a binary
  * `{:error, %Whiff.Error{reason: :unsupported_input}}` if `bytes` is not a binary

  ## Examples

      iex> input = Whiff.Input.from_binary("TRADE/1\\nid=1\\n", name: "pos.trade")
      iex> match?(%Whiff.Input{source: :binary, extension: ".trade", size: 14}, input)
      true

      iex> Whiff.Input.from_binary("x", name: :bad)
      {:error, %Whiff.Error{reason: :invalid_option, message: "name must be a string", path: nil, details: %{}}}

      iex> Whiff.Input.from_binary(:not_a_binary)
      {:error, %Whiff.Error{reason: :unsupported_input, message: "expected a binary", path: nil, details: %{}}}
  """
  @spec from_binary(binary(), keyword()) :: t() | {:error, Whiff.Error.t()}
  def from_binary(bytes, opts \\ [])

  def from_binary(bytes, opts) when is_binary(bytes) and is_list(opts) do
    filename = Keyword.get(opts, :name) || Keyword.get(opts, :filename)

    if not is_nil(filename) and not is_binary(filename) do
      {:error, Whiff.Error.new(:invalid_option, "name must be a string")}
    else
      filename = filename || "input.bin"

      %__MODULE__{
        source: :binary,
        bytes: bytes,
        filename: filename,
        extension: extension_of(filename),
        mime: Keyword.get(opts, :mime),
        size: byte_size(bytes)
      }
    end
  end

  def from_binary(_, _) do
    {:error, Whiff.Error.new(:unsupported_input, "expected a binary")}
  end

  @doc """
  Safe presentation map for logs and diagnostics.

  Never includes `:bytes`.

  ## Examples

      iex> input = Whiff.Input.from_binary(<<0, 1, 2>>, name: "x.bin", mime: "application/octet-stream")
      iex> Whiff.Input.present(input)
      %{source: :binary, path: nil, filename: "x.bin", extension: ".bin", mime: "application/octet-stream", size: 3}
  """
  @spec present(t()) :: map()
  def present(%__MODULE__{} = input) do
    %{
      source: input.source,
      path: input.path,
      filename: input.filename,
      extension: input.extension,
      mime: input.mime,
      size: input.size
    }
  end

  defp extension_of(filename) when is_binary(filename) do
    case Path.extname(filename) do
      "" -> nil
      ext -> String.downcase(ext)
    end
  end

  defp safe_size(path) do
    case File.stat(path) do
      {:ok, %{size: size}} -> size
      _ -> nil
    end
  end
end
