
build = find_program('build_recrust')
cargo = find_program('cargo')
infile = 'Cargo.toml'
outfile = 'librecrust.a'


env = environment()
env.set('_defaultCARGO', cargo.full_path())
env.set('SYSCONFDIR', conf.get('SYSCONFDIR').strip('"'))
env.set('NODCACHEDIRNOD', conf.get('NODCACHEDIRNOD').strip('"'))
env.set('NODCACHEDIRUDR', conf.get('NODCACHEDIRUDR').strip('"'))
env.set('builddir', '.')
env.set('srcdir', meson.current_source_dir())
# The two calls below set the env var to the empty string if it does not exist already and leave it alone otherwise
env.append('RUST_TARGET', '', separator: '')
env.append('RUSTC_TARGET_ARCH', '', separator: '')

if cargo.version().version_compare('>=1.88')
env.set('features', '--features pkcs12')
endif

opt_rust_args = get_option('rust-args')
if opt_rust_args != ''
  env.set('RUSTFLAGS', opt_rust_args)
endif

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
