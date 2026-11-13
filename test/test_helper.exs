exclude = [:slow] ++ if match?({:win32, _}, :os.type()), do: [:unix], else: []
ExUnit.start(exclude: exclude)
