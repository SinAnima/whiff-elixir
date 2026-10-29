defmodule Whiff.Plugin do
  @moduledoc false

  @doc """
  Run a zero-arity function in a monitored task with timeout.

  Returns:
  * `{:ok, value}` — function completed; `value` is whatever it returned
  * `{:error, %Whiff.Error{}}` — raise/throw/exit/timeout
  """
  @spec run((-> term()), keyword()) :: {:ok, term()} | {:error, Whiff.Error.t()}
  def run(fun, opts \\ []) when is_function(fun, 0) do
    timeout = Keyword.get(opts, :timeout, 5_000)
    kind = Keyword.get(opts, :kind, :extractor)
    id = Keyword.get(opts, :id, "plugin")

    task =
      Task.async(fn ->
        try do
          {:ok, fun.()}
        rescue
          e in Whiff.Error ->
            {:error, e}

          e ->
            {:error,
             Whiff.Error.new(error_reason(kind), Exception.message(e),
               details: %{plugin: id, class: e.__struct__}
             )}
        catch
          :throw, value ->
            {:error,
             Whiff.Error.new(error_reason(kind), "plugin threw: #{inspect(value)}",
               details: %{plugin: id}
             )}

          :exit, reason ->
            {:error,
             Whiff.Error.new(error_reason(kind), "plugin exited: #{inspect(reason)}",
               details: %{plugin: id}
             )}
        end
      end)

    case Task.yield(task, timeout) || Task.shutdown(task, :brutal_kill) do
      {:ok, {:ok, value}} ->
        {:ok, value}

      {:ok, {:error, %Whiff.Error{}} = err} ->
        err

      nil ->
        {:error,
         Whiff.Error.new(:timeout, "plugin timed out after #{timeout}ms", details: %{plugin: id})}

      {:exit, reason} ->
        {:error,
         Whiff.Error.new(error_reason(kind), "plugin task exited: #{inspect(reason)}",
           details: %{plugin: id}
         )}
    end
  end

  defp error_reason(:analyzer), do: :analyzer_error
  defp error_reason(_), do: :extractor_error
end
