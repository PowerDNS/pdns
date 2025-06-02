sources = files(
  'dnsdist-settings-generator.py',
  '../dnsdist-settings-definitions.yml',
  'dnsdist-configuration-yaml-items-generated-pre-in.cc',
  'rust-pre-in.rs',
  'rust-middle-in.rs',
  'rust-post-in.rs',
)

generated = [
  'dnsdist-configuration-yaml-items-generated.cc',
]

python = find_program('python3')

rust_lib_sources = custom_target(
  command: [python, '@INPUT0@', '@SOURCE_ROOT@', '@SOURCE_ROOT@/dnsdist-rust-lib', '@SOURCE_ROOT@', '@BUILD_ROOT@'],
  input: sources,
  output: generated,
)

dep_rust_lib = declare_dependency(
  sources: [rust_lib_sources,],
  include_directories: [include_directories('.'), ]
)

subdir('rust')
