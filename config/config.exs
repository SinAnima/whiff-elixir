import Config

# Library defaults. Host apps may override in their own config.
config :whiff,
  extractors: [],
  analyzers: [],
  # Bound concurrent DirtyCpu NIF calls (ETS semaphore).
  native_max_concurrency: 8,
  # Local scratch for `stage: :local` (nil → System.tmp_dir!()/whiff-scratch).
  scratch_dir: nil,
  scratch_max_bytes: 1_073_741_824
