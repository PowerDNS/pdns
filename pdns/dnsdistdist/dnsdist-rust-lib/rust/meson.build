build = find_program('build_dnsdist_rust_library')
cargo = find_program('cargo')
infile = 'Cargo.toml'
outfile = 'libdnsdist_rust.a'

env = environment()
env.set('_defaultCARGO', cargo.full_path())
env.set('SYSCONFDIR', conf.get('SYSCONFDIR'))
env.set('builddir', '.')
env.set('generatedheadersdir', meson.current_build_dir() + '/..')
env.set('srcdir', meson.current_source_dir())
# The two calls below set the env var to an empty string if it does not exist already and leave it alone otherwise
env.append('RUST_TARGET', '', separator: '')
env.append('RUSTC_TARGET_ARCH', '', separator: '')

if get_option('rust-lto') and get_option('b_lto') and get_option('b_lto_mode') == 'default'
  env.set('CARGO_LTO_MODE', 'fat')
  summary('LTO', true, bool_yn: true, section: 'Rust')
  summary('LTO mode', 'fat', section: 'Rust')
elif get_option('rust-lto') and get_option('b_lto') and get_option('b_lto_mode') == 'thin'
  env.set('CARGO_LTO_MODE', 'thin')
  summary('LTO', true, bool_yn: true, section: 'Rust')
  summary('LTO mode', 'thin', section: 'Rust')
else
  summary('LTO', false, bool_yn: true, section: 'Rust')
endif

lib_dnsdist_rust = custom_target('libdnsdist_rust.a',
  output: [outfile, 'cxx.h'],
  input: infile,
  command: [build,
  ],
  depend_files: [
    'Cargo.toml',
    'Cargo.lock',
    'src/helpers.rs',
  ],
  depends: rust_lib_sources,
  env: env,
  console: true,
)

dep_dnsdist_rust_lib = declare_dependency(
  link_with: lib_dnsdist_rust[0],
  sources: lib_dnsdist_rust[1],
  include_directories: [include_directories('..')],
)
