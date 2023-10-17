project(
  'pdns',
  ['c', 'cpp'],
  version: run_command('builder-support' / 'gen-version', check: true).stdout().strip(),
  license: 'GPLv2',
  license_files: 'NOTICE',
  meson_version: '>= 1.2.1',
  default_options: [
    'buildtype=debugoptimized',
    'warning_level=2',          # TODO Move this to 3 to enable -Wpedantic
    'cpp_std=c++17',
  ],
)

product_source_dir = meson.current_source_dir()
product_build_dir = meson.current_build_dir()
summary('Source Dir', product_source_dir, section: 'Build')
summary('Build Dir', product_build_dir, section: 'Build')

# Setup some modules
fs = import('fs')

# Create the configuration object and dependencies list.
conf = configuration_data()

# Toplevel includes
dep_pdns = declare_dependency(include_directories: include_directories('.', 'pdns'))

# Feature detection and system configuration
subdir('meson' / 'config')                  # Config
subdir('meson' / 'version')                 # Generate version define
subdir('meson' / 'compiler-setup')          # Common compiler setup
subdir('meson' / 'summary')                 # Print a system/project summary
subdir('meson' / 'sysconfdir')              # Sysconfdir
subdir('meson' / 'libdir')                  # Libdir
subdir('meson' / 'platform')                # Platform detection
subdir('meson' / 'timet-size')              # Check the size of time_t
subdir('meson' / 'timet-sign')              # Check the sign of time_t
subdir('meson' / 'atomics')                 # Check atomics support
subdir('meson' / 'pthread-headers')         # Check pthread headers
subdir('meson' / 'pthread-setname')         # Pthread setname madness
subdir('meson' / 'strerror')                # Strerror_r
subdir('meson' / 'lua')                     # Lua
subdir('meson' / 'lua-records')             # Lua-based Records
subdir('meson' / 'hardening')               # Hardening
subdir('meson' / 'kiss-rng')                # Unsafe KISS RNG
subdir('meson' / 'net-libs')                # Network Libraries
subdir('meson' / 'tm-gmtoff')               # Check for tm_gmtoff field in struct tm
subdir('meson' / 'mmap')                    # Check for mmap
subdir('meson' / 'libsodium')               # Libsodium-based signers
subdir('meson' / 'libdecaf')                # Libdecaf-based signers
subdir('meson' / 'libcrypto')               # OpenSSL-based signers
subdir('meson' / 'libssl')                  # OpenSSL libssl
subdir('meson' / 'gnutls')                  # GnuTLS
subdir('meson' / 'dot')                     # DNS over TLS
subdir('meson' / 'ipcipher')                # IPCipher
subdir('meson' / 'clock-gettime')           # Clock_gettime
subdir('meson' / 'boost')                   # Boost
subdir('meson' / 'boost-program-options')   # Boost Program Options Library
subdir('meson' / 'unit-tests')              # Unit Tests
subdir('meson' / 'auth-backend-unit-tests') # Auth Backend Unit Tests
subdir('meson' / 'reproducible')            # Reproducible Builds
subdir('meson' / 'fuzz-targets')            # Fuzzing Targets
subdir('meson' / 'dlopen')                  # dlopen
subdir('meson' / 'verbose-logging')         # Verbose Logging
subdir('meson' / 'pkcs11')                  # PKCS11
subdir('meson' / 'gss-tsig')                # GSS-TSIG
subdir('meson' / 'auth-tools')              # Tools
subdir('meson' / 'ixfrdist')                # Ixfrdist
subdir('meson' / 'systemd')                 # Systemd and unit file handling
subdir('meson' / 'code-coverage')           # Code coverage
subdir('meson' / 'auto-var-init')           # Automatic Variable Initialization
subdir('meson' / 'sanitizers')              # Sanitizers
subdir('meson' / 'malloc-trace')            # Malloc-trace
subdir('meson' / 'socket-dir')              # Socket Dir
subdir('meson' / 'various-functions')       # Various Functions
subdir('meson' / 'various-headers')         # Various Headers

# Manpages
# if not fs.exists('docs' / 'pdns_server.1') and not python_have_venv
#   warning('Python3 and/or its venv module is not available and ' +
#           '`docs/pdns_server.1` cannot be found. ' +
#           'Documentation will not be built.')
# endif
# TODO Generate pdns_server.1 manpage

# Ext
ext_modules = ['arc4random', 'yahttp', 'ipcrypt', 'json11', 'protozero']
subdir('ext')

deps = [
  dep_pdns,
  dep_platform,
  dep_atomics,
  dep_threads,
  dep_lua,
  dep_lua_records,
  dep_netlibs,
  dep_libsodium,
  dep_libdecaf,
  dep_libcrypto,
  dep_libssl,
  dep_gnutls,
  dep_rt,
  dep_boost,
  dep_boost_program_options,
  dep_unittests,
  dep_backend_unittests,
  dep_dlopen,
  dep_pkcs11,
  dep_gss_tsig,
  dep_ixfrdist,
  dep_yahttp,
  dep_ipcrypt,
  dep_json11,
  dep_arc4random,
  dep_systemd,
  dep_protozero,
]

# Modules
all_modules = {
  'bind':     {'deps': [],                              'exts': []},
  'pipe':     {'deps': [],                              'exts': []},
  'gmysql':   {'deps': ['mysql'],                       'exts': []},
  'godbc':    {'deps': ['odbc'],                        'exts': []},
  'gpgsql':   {'deps': ['pgsql'],                       'exts': []},
  'gsqlite3': {'deps': ['sqlite3'],                     'exts': []},
  'ldap':     {'deps': ['ldap'],                        'exts': []},
  'lua2':     {'deps': [],                              'exts': []},
  'remote':   {'deps': ['prog-curl', 'zeromq'],         'exts': []},
  'tinydns':  {'deps': ['cdb'],                         'exts': []},
  'geoip':    {'deps': ['geoip', 'mmdb', 'yaml-cpp'],   'exts': []},
  'lmdb':     {'deps': ['lmdb', 'boost-serialization'], 'exts': ['lmdb-safe']},
}

# Configure module dependencies
foreach module_name, module_props: all_modules
  module_opt = get_option('module-' + module_name)
  module_deps = module_props['deps']

  if module_opt == 'disabled'
    continue
  endif

  foreach dep: module_deps
    if module_name == 'remote'
      if dep == 'prog-curl'
        if not opt_unittests
          continue                # We only need cURL for unit tests.
        endif
      elif dep == 'zeromq'
        if not get_option('module-remote-zeromq')
          continue
        endif
      endif
    endif

    subdir('meson' / dep)
  endforeach
endforeach

# Add the sqlite3 dependency for the bind and gsqlite3 backends and pdnsutil.
deps += get_variable('dep_sqlite3', dependency('', required: false))

subdir('pdns')

selected_modules = []
selected_dyn_modules = []
dep_modules = []
foreach module_name, module_props: all_modules
  module_backend_name = module_name + 'backend'
  module_opt = get_option('module-' + module_name)
  module_exts = module_props['exts']

  if module_opt == 'disabled'
    continue
  elif module_opt == 'static'
    selected_modules += module_name
  else
    selected_dyn_modules += module_name
  endif

  foreach ext: module_exts
    subdir('ext' / ext)
  endforeach

  subdir('modules' / module_backend_name)
  dep_modules += get_variable('dep_' + module_backend_name)
endforeach

conf.set_quoted(
  'PDNS_MODULES',
  ' '.join(selected_modules),
  description: 'Built-in modules'
)

conf.set_quoted(
  'PDNS_DYN_MODULES',
  ' '.join(selected_dyn_modules),
  description: 'Dynamically loadable modules built along with pdns'
)

# Generate config.h
config_h = configure_file(configuration: conf, output: 'config.h')

pdns_auth = executable(
  'pdns-auth',
  config_h,
  export_dynamic: true,
  dependencies: [
    dep_modules,
    libpdns,
    libpdns_auth,
    libpdns_auth_main,
    libpdns_auth_ws,
    libpdns_lua_records,
  ],
)

pdns_util = executable(
  'pdns-util',
  config_h,
  dependencies: [
    libpdns_auth,
    libpdns_base,
    libpdns_util,
  ],
)
