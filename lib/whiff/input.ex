defmodule Whiff.Input do
  @moduledoc """
  Canonical description of an extraction input.

  For `:binary` sources, `bytes` may hold the payload for plugin use, but
  presentation helpers never dump raw content into logs or error details.
  """

  @enforce_keys [:source]
  defstruct source: nil,
            path: nil,
            bytes: nil,
            filename: nil,
            extension: nil,
            mime: nil,
            size: nil

  @type source :: :path | :binary

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
  Build input from a filesystem path.
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
  Build input from in-memory bytes.
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
  Safe map for diagnostics — never includes raw bytes.
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
