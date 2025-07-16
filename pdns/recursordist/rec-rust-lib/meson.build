sources = files(
  'generate.py',
  'docs-new-preamble-in.rst',
  'docs-old-preamble-in.rst',
  'rust-bridge-in.rs',
  'rust-preamble-in.rs',
  'table.py',
)

generated = [
  'cxxsettings-generated.cc',
]

python = find_program('python3')

recrust = custom_target(
  command: [python, '@INPUT0@', '@SOURCE_ROOT@/rec-rust-lib', '@BUILD_ROOT@/rec-rust-lib'],
  input: sources,
  output: generated,
)

# librec_common depends on this, so the sources get linked
dep_recrust_ch = declare_dependency(
  sources: [recrust, 'cxxsupport.cc'],
  include_directories: [include_directories('.'), ]
)

# The rust parts depend on this, no sources listed, which avoid duplicates object files
# In turn deps (defined in the main meson.build file, includes dep_rust_recrust)
dep_recrust = declare_dependency(
  include_directories: [include_directories('.'), ]
)

subdir('rust')

