sources = files(
  'generate.py',
  'docs-new-preamble-in.rst',
  'docs-old-preamble-in.rst',
  'rust-bridge-in.rs',
  'rust-preamble-in.rs',
  'table.py',
)

generated = [
  'timestamp',
]

python = find_program('python3')

settings = custom_target(
  command: [python, '@INPUT0@', '@SOURCE_ROOT@/settings', '@BUILD_ROOT@/settings'],
  input: sources,
  output: generated,
)

subdir('rust')

dep_settings = declare_dependency(
  dependencies: dep_rust_settings,
  sources: [settings, 'cxxsupport.cc', 'cxxsettings-generated.cc'],
  include_directories: [include_directories('.'), ]
)

