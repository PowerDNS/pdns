sources = files(
  'dnsdist-settings-generator.py',
  '../dnsdist-settings-definitions.yml',
  'dnsdist-configuration-yaml-items-generated-pre-in.cc',
  'dnsdist-configuration-yaml-items-generated.cc',
  'dnsdist-settings-documentation-generator.py',
  'rust-pre-in.rs',
  'rust-middle-in.rs',
  'rust-post-in.rs',
)

generated = [
  'dnsdist-configuration-yaml-items-generated.cc',
]

python = find_program('python3')

rust_lib_sources = custom_target(
  command: [python, '@INPUT0@', '@INPUT1@', '@SOURCE_ROOT@/dnsdist-rust-lib', '@BUILD_ROOT@/dnsdist-rust-lib'],
  input: sources,
  output: generated,
)

dep_rust_lib = declare_dependency(
  sources: [rust_lib_sources,],
  include_directories: [include_directories('.'), ]
)

subdir('rust')
