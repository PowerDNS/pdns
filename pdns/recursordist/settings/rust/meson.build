
build = find_program('build_settings')
cargo = find_program('cargo')
infile = 'Cargo.toml'
outfile = 'libsettings.a'


env = environment()
env.append('CARGO', cargo.full_path())
env.append('SYSCONFDIR', conf.get('SYSCONFDIR'))
env.append('NODCACHEDIRNOD', 'XXXlocalstatedir/nod')
env.append('NODCACHEDIRUDR', 'XXXlocalstatedir/udr')
env.append('builddir', '.')
env.append('srcdir', meson.current_source_dir())
env.append('RUST_TARGET', '')
env.append('RUSTC_TARGET_ARCH', '')

lib_settings = custom_target('libsettings.a',
  output: [outfile, 'cxx.h'],
  input: infile,
  command: [build,
  ],
  depend_files: [
    'src/bridge.hh',
    'src/bridge.rs',
    'src/helpers.rs',
  ],
  depends: settings,
  env: env,
)

dep_rust_settings = declare_dependency(
  link_with: lib_settings[0],
  sources: lib_settings[1],
  include_directories: [include_directories('.'), include_directories('src')]
)
