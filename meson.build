project(
  'pdns',
  ['c', 'cpp'],
  version: run_command('builder-support' / 'gen-version', check: true).stdout().strip(),
  # license_files: 'LICENSE',   # TODO Meson 1.1.0
  meson_version: '>= 0.53',
  default_options: [
    'buildtype=debugoptimized',
    'warning_level=2',          # TODO Move this to 3 at some point to enable -Wpedantic
    'cpp_std=c++17',
  ],
)

# TODO Meson 0.56 introduces meson.project_source_root().
product_source_dir = meson.current_source_dir()
product_build_dir = meson.current_build_dir()
summary('Source Dir', product_source_dir, section: 'Build')
summary('Build Dir', product_build_dir, section: 'Build')

# Setup some modules
fs = import('fs')

# Create the configuration object and dependencies list.
conf = configuration_data()
deps = []

subdir('meson' / 'config')                  # Config
subdir('meson' / 'version')                 # Generate version define
subdir('meson' / 'compiler-setup')          # Common compiler setup
subdir('meson' / 'summary')                 # Print a system/project summary
subdir('meson' / 'timet-size')              # Check the size of time_t
subdir('meson' / 'timet-sign')              # Check the sign of time_t
subdir('meson' / 'flex')                    # Find flex and create generator
subdir('meson' / 'bison')                   # Find bison and create generator
subdir('meson' / 'platform')                # Platform detection
subdir('meson' / 'atomics')                 # Check atomics support
subdir('meson' / 'pthread-headers')         # Check pthread headers
subdir('meson' / 'pthread-setname')         # Pthread setname madness
subdir('meson' / 'strerror')                # Strerror_r
subdir('meson' / 'lua')                     # Lua
subdir('meson' / 'lua-records')             # Lua Records
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
subdir('meson' / 'ragel')                   # Find Ragel and create generator
subdir('meson' / 'clock-gettime')           # Clock_gettime
subdir('meson' / 'boost')                   # Boost
subdir('meson' / 'boost-program-options')   # Boost Program Options Library
subdir('meson' / 'unit-tests')              # Unit Tests
subdir('meson' / 'auth-backend-unit-tests') # Auth Backend Unit Tests
subdir('meson' / 'reproducible')            # Reproducible Builds
subdir('meson' / 'fuzz-targets')            # Fuzzing Targets
subdir('meson' / 'python-venv')             # Python Venv
subdir('meson' / 'from-git')                # From Git
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
subdir('meson' / 'auth-socket-dir')         # Socket Dir
subdir('meson' / 'auth-various-functions')  # Various Functions

# Find ragel or pdns/dnslabeltext.cc
if not ragel.found() and not fs.exists('pdns' / 'dnslabeltext.cc')
  error('Ragel is missing and `pdns/dnslabeltext.cc` cannot be found. ' +
        'Install Ragel or download the sources from www.powerdns.com')
endif

# Swagger
if not fs.exists('pdns' / 'api-swagger.json') and not python_have_venv
  error('Python3 and/or its venv module is not available and ' +
        '`pdns/api-swagger.json` cannot be found. ' +
        'The Authoritative Server cannot be built.')
endif
# TODO Generate api-swagger.json

# Manpages
if not fs.exists('docs' / 'pdns_server.1') and not python_have_venv
  warning('Python3 and/or its venv module is not available and ' +
          '`docs/pdns_server.1` cannot be found. ' +
          'Documentation will not be built.')
endif
# TODO Generate pdns_server.1 manpage

# TODO Ultimately we should get rid of this by passing library objects instead of include
# directories to e.g. modules.
toplevel_includes = include_directories('.', 'pdns')

# Modules
all_modules = {
  'bind':     [],
  'pipe':     [],
  'gmysql':   ['mysql'],
  'godbc':    ['odbc'],
  'gpgsql':   ['pgsql'],
  'gsqlite3': ['sqlite3'],
  'ldap':     ['ldap'],
  'lua2':     [],
  'remote':   ['prog-curl', 'zeromq'],
  'tinydns':  ['cdb'],
  'geoip':    ['geoip'],
  'lmdb':     ['lmdb', 'boost-serialization'],
}
selected_modules = []
selected_dyn_modules = []
foreach module_name, module_deps: all_modules
  module_backend_name = module_name + 'backend'
  module_opt = get_option('module-' + module_name)
  module_opt_dyn = get_option('module-' + module_name + '-dyn')

  if module_name == 'remote' and (module_opt != 'disabled' or module_opt_dyn != 'disabled')
    set_variable(module_name + '_module', module_opt != 'disabled')
    set_variable(module_name + '_dyn_module', module_opt_dyn != 'disabled')

    selected_modules += module_opt != 'disabled' ? module_name : []
    selected_dyn_modules += module_opt_dyn != 'disabled' ? module_name : []

    foreach dep: module_deps
      if dep == 'prog-curl'
        if not opt_unittests
          continue                # We only need cURL for unit tests.
        endif
      elif dep == 'zeromq'
        if module_opt != 'with-zeromq' and module_opt_dyn != 'with-zeromq'
          continue
        endif
      endif

      subdir('meson' / dep)
    endforeach
  elif module_opt or module_opt_dyn
    set_variable(module_name + '_module', module_opt)
    set_variable(module_name + '_dyn_module', module_opt_dyn)

    selected_modules += module_opt ? module_name : []
    selected_dyn_modules += module_opt_dyn ? module_name : []

    foreach dep: module_deps
      subdir('meson' / dep)
    endforeach
  else
    continue
  endif

  subdir('modules' / module_backend_name)
endforeach

conf.set_quoted('PDNS_MODULES', ' '.join(selected_modules), description: 'Built-in modules')
conf.set_quoted('PDNS_DYN_MODULES', ' '.join(selected_dyn_modules), description: 'Dynamically loadable modules that were built along with pdns')

# Ext
ext_modules = ['yahttp', 'ipcrypt']
subdir('ext')

# Generate config.h ----------------------------------------------------------------------
config_h = configure_file(configuration: conf, output: 'config.h')
# summary('Defines', conf.keys(), section: 'Build Configuration') # TODO Meson 0.57

# TODO: Add source files
auth = executable('pdns', config_h, dependencies: deps, export_dynamic: true)
