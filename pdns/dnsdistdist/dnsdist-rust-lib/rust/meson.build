build = find_program('build_dnsdist_rust_library')
cargo = find_program('cargo')
infile = 'Cargo.toml'
outfile = 'libdnsdist_rust.a'

env = environment()
env.append('CARGO', cargo.full_path())
env.append('SYSCONFDIR', conf.get('SYSCONFDIR'))
env.append('builddir', '.')
env.append('generatedheadersdir', meson.current_build_dir() + '/..')
env.append('srcdir', meson.current_source_dir())
env.append('RUST_TARGET', '')
env.append('RUSTC_TARGET_ARCH', '')

lib_dnsdist_rust = custom_target('libdnsdist_rust.a',
  output: [outfile, 'cxx.h'],
  input: infile,
  command: [build,
  ],
  depend_files: [
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
