sources = files(
  'dnsdist-settings-generator.py',
  '../dnsdist-settings-definitions.yml',
  'dnsdist-configuration-yaml-items-pre-in.cc',
  'rust-pre-in.rs',
  'rust-middle-in.rs',
  'rust-post-in.rs',
)

generated = [
  'dnsdist-configuration-yaml-items-generated.cc',
  'dnsdist-rust-bridge-actions-generated.hh',
  'dnsdist-rust-bridge-actions-generated-body.hh',
  'dnsdist-rust-bridge-selectors-generated.hh',
  'dnsdist-rust-bridge-selectors-generated-body.hh',
]

python = find_program('python3')

rust_lib_sources = custom_target(
  command: [python, '@INPUT0@', '@SOURCE_ROOT@', '@SOURCE_ROOT@/dnsdist-rust-lib', '@OUTDIR@'],
  input: sources,
  output: generated,
)

dep_rust_lib = declare_dependency(
  sources: [
    rust_lib_sources[1],
    rust_lib_sources[2],
    rust_lib_sources[3],
    rust_lib_sources[4],
  ],
  include_directories: [
    include_directories('.'),
  ]
)

if get_option('yaml').allowed()
  subdir('rust')
else
  dep_dnsdist_rust_lib = declare_dependency()
endif
