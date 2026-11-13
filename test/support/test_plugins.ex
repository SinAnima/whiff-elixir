defmodule Whiff.Test.Plugin do
  @moduledoc false
  # Builds small test extractors with `use Whiff.Test.Plugin, id: ..., ext: ...`.

  defmacro __using__(opts) do
    quote bind_quoted: [opts: opts] do
      @behaviour Whiff.Extractor
      @plugin_id Keyword.fetch!(opts, :id)
      @plugin_ext Keyword.get(opts, :ext)

      @impl true
      def id, do: @plugin_id

      @impl true
      def version, do: 1

      @impl true
      def supports?(%Whiff.Input{extension: ext}, _native), do: @plugin_ext in [nil, ext]
    end
  end
end

defmodule Whiff.Test.TitleWhiffer do
  @moduledoc false
  use Whiff.Test.Plugin, id: "test.title", ext: ".txt"

  @impl true
  def extract(_input, _native), do: {:ok, %{"content" => %{"title" => "plugin title"}}}
end

defmodule Whiff.Test.FirstDup do
  @moduledoc false
  use Whiff.Test.Plugin, id: "test.first", ext: ".dup"

  @impl true
  def extract(_input, _native),
    do: {:ok, %{"content" => %{"title" => "first"}, "format" => %{"test.first" => %{"n" => 1}}}}
end

defmodule Whiff.Test.SecondDup do
  @moduledoc false
  use Whiff.Test.Plugin, id: "test.second", ext: ".dup"

  @impl true
  def extract(_input, _native),
    do: {:ok, %{"content" => %{"title" => "second"}, "format" => %{"test.second" => %{"n" => 2}}}}
end

defmodule Whiff.Test.KillingExtractor do
  @moduledoc false
  use Whiff.Test.Plugin, id: "test.kill"

  @impl true
  def extract(_input, _native), do: Process.exit(self(), :kill)
end

defmodule Whiff.Test.LinkedCrashExtractor do
  @moduledoc false
  use Whiff.Test.Plugin, id: "test.linked_crash"

  @impl true
  def extract(_input, _native) do
    spawn_link(fn -> exit(:boom) end)
    Process.sleep(1_000)
    {:ok, %{}}
  end
end

defmodule Whiff.Test.RaisingSupports do
  @moduledoc false
  @behaviour Whiff.Extractor

  @impl true
  def id, do: "test.raising_supports"

  @impl true
  def version, do: 1

  @impl true
  def supports?(_input, _native), do: raise("supports exploded")

  @impl true
  def extract(_input, _native), do: {:ok, %{}}
end

defmodule Whiff.Test.LeakyExtractor do
  @moduledoc false
  use Whiff.Test.Plugin, id: "test.leaky"

  @secret "jane.doe@example.com password=hunter2"

  @impl true
  def extract(%Whiff.Input{filename: name}, _native) do
    case name do
      "return.txt" -> {:weird, @secret}
      "throw.txt" -> throw(@secret)
      "raise.txt" -> raise ArgumentError, @secret
      "exit.txt" -> exit({:shutdown, @secret})
      _ -> {:error, Whiff.Error.new(:extractor_error, "failed for " <> @secret)}
    end
  end
end

defmodule Whiff.Test.PatchExtractor do
  @moduledoc false
  # Returns the patch stored in the process dictionary of the test via the
  # input MIME field (a key into :persistent_term).
  use Whiff.Test.Plugin, id: "test.patch"

  @impl true
  def extract(%Whiff.Input{mime: key}, _native), do: {:ok, :persistent_term.get({__MODULE__, key})}

  def put(key, patch), do: :persistent_term.put({__MODULE__, key}, patch)
end

defmodule Whiff.Test.NativeIdExtractor do
  @moduledoc false
  use Whiff.Test.Plugin, id: "text.plain"

  @impl true
  def extract(_input, _native), do: {:ok, %{"format" => %{"x.y" => %{}}}}
end

defmodule Whiff.Test.BadIdExtractor do
  @moduledoc false
  @behaviour Whiff.Extractor

  @impl true
  def id, do: :not_a_string

  @impl true
  def version, do: 1

  @impl true
  def supports?(_input, _native), do: true

  @impl true
  def extract(_input, _native), do: {:ok, %{}}
end

defmodule Whiff.Test.RiskAnalyzer do
  @moduledoc false
  @behaviour Whiff.Analyzer

  @impl true
  def id, do: "test.risk"

  @impl true
  def version, do: 2

  @impl true
  def analyze(_report, _input) do
    {:ok,
     %{
       "security" => %{
         "risks" => [
           %{
             "kind" => "custom_flag",
             "category" => "other",
             "severity" => "low",
             "detail" => "test"
           }
         ]
       }
     }}
  end
end

defmodule Whiff.Test.NotAPlugin do
  @moduledoc false
end

defmodule Whiff.Test.BadVersionExtractor do
  @moduledoc false
  @behaviour Whiff.Extractor

  @impl true
  def id, do: "test.bad_version"

  @impl true
  def version, do: -1

  @impl true
  def supports?(_input, _native), do: true

  @impl true
  def extract(_input, _native), do: {:ok, %{}}
end

defmodule Whiff.Test.BadReturnAnalyzer do
  @moduledoc false
  @behaviour Whiff.Analyzer

  @impl true
  def id, do: "test.bad_return"

  @impl true
  def version, do: 1

  @impl true
  def analyze(_report, %Whiff.Input{filename: "long.txt"}),
    do: {:error, Whiff.Error.new(:analyzer_error, String.duplicate("é", 400))}

  def analyze(_report, _input), do: %{"not" => "a tuple"}
end
