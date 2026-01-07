
build = find_program('build_recrust')
cargo = find_program('cargo')
infile = 'Cargo.toml'
outfile = 'librecrust.a'


env = environment()
env.append('CARGO', cargo.full_path())
env.append('SYSCONFDIR', conf.get('SYSCONFDIR').strip('"'))
env.append('NODCACHEDIRNOD', conf.get('NODCACHEDIRNOD').strip('"'))
env.append('NODCACHEDIRUDR', conf.get('NODCACHEDIRUDR').strip('"'))
env.append('builddir', '.')
env.append('srcdir', meson.current_source_dir())
env.append('RUST_TARGET', '')
env.append('RUSTC_TARGET_ARCH', '')

lib_recrust = custom_target('librecrust.a',
  output: [outfile, 'cxx.h', 'lib.rs.h', 'misc.rs.h', 'web.rs.h'],
  input: infile,
  command: [build,
  ],
  depend_files: [
    'Cargo.toml',
    'Cargo.lock',
    'src/bridge.hh',
    'src/bridge.rs',
    'src/helpers.rs',
    'src/misc.rs',
    'src/web.rs',
  ],
  depends: recrust,
  env: env,
  console: true,
)

dep_rust_recrust = declare_dependency(
  link_with: lib_recrust[0],
  sources: lib_recrust[1],
  include_directories: [include_directories('.'), include_directories('src')],
)
