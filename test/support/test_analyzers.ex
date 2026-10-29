defmodule Whiff.Test.TitleAnalyzer do
  @moduledoc false
  @behaviour Whiff.Analyzer

  @impl true
  def id, do: "test.title_analyzer"

  @impl true
  def version, do: 1

  @impl true
  def analyze(report, _input) do
    title = get_in(report, ["content", "title"]) || "untitled"

    {:ok,
     %{
       "metadata" => %{
         "test.title_analyzer" => %{"normalized_title" => String.upcase(to_string(title))}
       }
     }}
  end
end

defmodule Whiff.Test.RaisingAnalyzer do
  @moduledoc false
  @behaviour Whiff.Analyzer

  @impl true
  def id, do: "test.raising_analyzer"

  @impl true
  def version, do: 1

  @impl true
  def analyze(_report, _input), do: raise("boom")
end

defmodule Whiff.Test.SlowExtractor do
  @moduledoc false
  @behaviour Whiff.Extractor

  @impl true
  def id, do: "test.slow"

  @impl true
  def version, do: 1

  @impl true
  def supports?(%Whiff.Input{extension: ".slow"}, _), do: true
  def supports?(_, _), do: false

  @impl true
  def extract(_input, _native) do
    Process.sleep(5_000)
    {:ok, %{"content" => %{"title" => "late"}}}
  end
end

defmodule Whiff.Test.SecretWhiffer do
  @moduledoc false
  @behaviour Whiff.Extractor

  @impl true
  def id, do: "test.secret"

  @impl true
  def version, do: 1

  @impl true
  def supports?(%Whiff.Input{extension: ".secret"}, _), do: true
  def supports?(_, _), do: false

  @impl true
  def extract(_input, _native) do
    {:ok,
     %{
       "content" => %{
         "title" => "leak",
         "excerpt" => "contact me at agent@example.com password=hunter2"
       },
       "format" => %{"test.secret" => %{"note" => "ok"}}
     }}
  end
end

defmodule Whiff.Test.AugmentPdfWhiffer do
  @moduledoc false
  @behaviour Whiff.Extractor

  @impl true
  def id, do: "test.pdf_augment"

  @impl true
  def version, do: 1

  @impl true
  def supports?(%Whiff.Input{extension: ext}, _native) when ext in [".txt", ".pdf"], do: true
  def supports?(_, _), do: false

  @impl true
  def extract(_input, _native) do
    {:ok,
     %{
       "format" => %{"test.pdf_augment" => %{"reviewed" => true}},
       "content" => %{"keywords" => ["augmented"]}
     }}
  end
end
