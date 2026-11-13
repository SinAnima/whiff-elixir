defmodule Whiff.Application do
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    children = [
      # Bounds concurrent native extractions (see Whiff.Limiter).
      Whiff.Limiter,
      # Unlinked tasks for extract_many/2.
      {Task.Supervisor, name: Whiff.TaskSupervisor}
    ]

    Supervisor.start_link(children, strategy: :one_for_one, name: Whiff.Supervisor)
  end
end
