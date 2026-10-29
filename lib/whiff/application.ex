defmodule Whiff.Application do
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    # Bound concurrent native extractions to reduce abandoned-thread pileup.
    :ok = ensure_native_limiter()

    children = []
    opts = [strategy: :one_for_one, name: Whiff.Supervisor]
    Supervisor.start_link(children, opts)
  end

  defp ensure_native_limiter do
    case :ets.whereis(:whiff_native_limiter) do
      :undefined ->
        :ets.new(:whiff_native_limiter, [
          :named_table,
          :public,
          :set,
          read_concurrency: true,
          write_concurrency: true
        ])

        :ets.insert(:whiff_native_limiter, {:max, 8})
        :ets.insert(:whiff_native_limiter, {:current, 0})
        :ok

      _ ->
        :ok
    end
  end
end
