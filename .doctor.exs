%Doctor.Config{
  ignore_modules: [
    Whiff.Application,
    Whiff.Native,
    Whiff.Limiter,
    Whiff.Options,
    Whiff.Plugin,
    Whiff.Registry
  ],
  ignore_paths: [
    ~r(test/),
    ~r(examples/)
  ],
  min_module_doc_coverage: 80,
  min_module_spec_coverage: 50,
  min_overall_doc_coverage: 70,
  min_overall_moduledoc_coverage: 80,
  min_overall_spec_coverage: 40,
  exception_moduledoc_required: true,
  raise: true,
  reporter: Doctor.Reporters.Full,
  struct_type_spec_required: true,
  umbrella: false
}
