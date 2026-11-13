defmodule Whiff.Limiter do
  @moduledoc false

  # Semaphore bounding concurrent native (NIF) calls.
  #
  # Each holder is monitored, so a slot is freed when its process exits for
  # any reason, including `:kill`. Waiters are served in FIFO order. A waiter
  # that does not get a slot within `wait_ms` receives
  # `{:error, %Whiff.Error{reason: :overloaded}}`; the limit is never
  # bypassed under load.
  #
  # Application config:
  #
  #   * `:native_max_concurrency` — slots (1..128, default 8)
  #   * `:native_wait_ms` — queue wait budget (1..3_600_000 ms, default 60_000)

  use GenServer

  alias Whiff.Error

  @default_max 8
  @default_wait_ms 60_000

  @typedoc "Snapshot returned by `stats/1`."
  @type stats :: %{
          current: non_neg_integer(),
          max: pos_integer(),
          waiting: non_neg_integer(),
          wait_ms: pos_integer()
        }

  @doc """
  Start a limiter.

  Options: `:name` (default `#{inspect(__MODULE__)}`), `:max`, `:wait_ms`.
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) do
    {name, opts} = Keyword.pop(opts, :name, __MODULE__)
    GenServer.start_link(__MODULE__, opts, name: name)
  end

  @doc """
  Run `fun` while holding a slot.

  Returns `fun.()` or `{:error, %Whiff.Error{reason: :overloaded}}` when no
  slot frees up within the wait budget. When the limiter process is not
  running (for example the `:whiff` application was not started) `fun` runs
  without a slot.

  Options: `:server` (default `#{inspect(__MODULE__)}`).
  """
  @spec with_native((-> result), keyword()) :: result | {:error, Error.t()} when result: var
  def with_native(fun, opts \\ []) when is_function(fun, 0) do
    server = Keyword.get(opts, :server, __MODULE__)

    case acquire(server) do
      {:ok, ref} ->
        try do
          fun.()
        after
          GenServer.cast(server, {:release, ref})
        end

      :not_running ->
        fun.()

      {:error, %Error{}} = err ->
        err
    end
  end

  @doc "Current slot usage."
  @spec stats(GenServer.server()) :: stats()
  def stats(server \\ __MODULE__), do: GenServer.call(server, :stats)

  defp acquire(server) do
    if GenServer.whereis(server) do
      GenServer.call(server, :acquire, :infinity)
    else
      :not_running
    end
  catch
    :exit, {:noproc, _} -> :not_running
  end

  @impl true
  def init(opts) do
    max = bounded(Keyword.get(opts, :max, config(:native_max_concurrency)), 1, 128, @default_max)

    wait_ms =
      bounded(Keyword.get(opts, :wait_ms, config(:native_wait_ms)), 1, 3_600_000, @default_wait_ms)

    {:ok, %{max: max, wait_ms: wait_ms, holders: %{}, queue: :queue.new(), waiting: %{}}}
  end

  @impl true
  def handle_call(:acquire, {pid, _} = from, state) do
    mon = Process.monitor(pid)

    if map_size(state.holders) < state.max do
      {:reply, {:ok, mon}, put_holder_ref(state, mon)}
    else
      timer = Process.send_after(self(), {:expire, mon}, state.wait_ms)
      waiting = Map.put(state.waiting, mon, {from, timer})
      {:noreply, %{state | queue: :queue.in(mon, state.queue), waiting: waiting}}
    end
  end

  def handle_call(:stats, _from, state) do
    {:reply,
     %{
       current: map_size(state.holders),
       max: state.max,
       waiting: map_size(state.waiting),
       wait_ms: state.wait_ms
     }, state}
  end

  @impl true
  def handle_cast({:release, mon}, state) do
    Process.demonitor(mon, [:flush])
    {:noreply, state |> drop_holder(mon) |> grant_next()}
  end

  @impl true
  def handle_info({:DOWN, mon, :process, _pid, _reason}, state) do
    cond do
      Map.has_key?(state.holders, mon) ->
        {:noreply, state |> drop_holder(mon) |> grant_next()}

      Map.has_key?(state.waiting, mon) ->
        {:noreply, drop_waiter(state, mon)}

      true ->
        {:noreply, state}
    end
  end

  def handle_info({:expire, mon}, state) do
    case Map.fetch(state.waiting, mon) do
      {:ok, {from, _timer}} ->
        Process.demonitor(mon, [:flush])

        GenServer.reply(
          from,
          {:error,
           Error.new(:overloaded, "no native slot within #{state.wait_ms}ms",
             details: %{max: state.max, wait_ms: state.wait_ms}
           )}
        )

        {:noreply, drop_waiter(state, mon)}

      :error ->
        {:noreply, state}
    end
  end

  # The caller's monitor ref doubles as the release token.
  defp put_holder_ref(state, mon), do: %{state | holders: Map.put(state.holders, mon, true)}

  defp drop_holder(state, mon), do: %{state | holders: Map.delete(state.holders, mon)}

  defp drop_waiter(state, mon) do
    {entry, waiting} = Map.pop(state.waiting, mon)

    with {_from, timer} <- entry, do: Process.cancel_timer(timer)

    %{state | waiting: waiting, queue: :queue.delete(mon, state.queue)}
  end

  defp grant_next(state) do
    if map_size(state.holders) < state.max do
      case :queue.out(state.queue) do
        {{:value, mon}, queue} ->
          {{from, timer}, waiting} = Map.pop(state.waiting, mon)
          Process.cancel_timer(timer)
          GenServer.reply(from, {:ok, mon})
          grant_next(%{put_holder_ref(state, mon) | queue: queue, waiting: waiting})

        {:empty, _} ->
          state
      end
    else
      state
    end
  end

  defp config(key), do: Application.get_env(:whiff, key)

  defp bounded(n, lo, hi, _default) when is_integer(n) and n >= lo and n <= hi, do: n
  defp bounded(_n, _lo, _hi, default), do: default
end
