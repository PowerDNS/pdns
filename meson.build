project(
  'pdns',
  ['c', 'cpp'],
  # version: 4.7.0,             # TODO This should call builder-support/gen-version
  # license_files: 'LICENse',   # TODO Meson 1.1.0
  meson_version: '>= 0.53',
  default_options: [
    'buildtype=debugoptimized',
    'warning_level=2',          # TODO Move this to 3 at some point to enable -Wpedantic
    'cpp_std=c++17',
  ],
)

summary('Source Dir', meson.current_source_dir(), section: 'Build')
summary('Build Dir', meson.current_build_dir(), section: 'Build')

# Setup some modules
fs = import('fs')

# Create the configuration object and dependencies list.
conf = configuration_data()
deps = []

subdir('meson/compiler-setup')           # Common compiler setup (cxx is the C++ compiler)
subdir('meson/summary')                  # Print a system/project summary
subdir('meson/timet-size')               # Check the size of time_t
subdir('meson/timet-sign')               # Check the sign of time_t
subdir('meson/prog-flex')                # Find flex
subdir('meson/prog-bison')               # Find bison
subdir('meson/platform')                 # Platform detection
subdir('meson/atomics')                  # Check atomics support
subdir('meson/pthread-headers')          # Check pthread headers
subdir('meson/pthread-setname')          # Pthread setname madness
subdir('meson/strerror')                 # Strerror_r
subdir('meson/lua')                      # Lua
subdir('meson/lua-records')              # Lua Records
subdir('meson/hardening')                # Hardening
subdir('meson/kiss-rng')                 # Unsafe KISS RNG
subdir('meson/net-libs')                 # Network Libraries
subdir('meson/tm-gmtoff')                # Check for the tm_gmtoff field in struct tm
subdir('meson/mmap')                     # Check for mmap
subdir('meson/libsodium')                # Libsodium-based signers
subdir('meson/libdecaf')                 # Libdecaf-based signers
subdir('meson/libcrypto')                # OpenSSL-based signers
subdir('meson/libssl')                   # OpenSSL libssl
subdir('meson/gnutls')                   # GnuTLS
subdir('meson/dot')                      # DNS over TLS
subdir('meson/ipcipher')                 # IPCipher
subdir('meson/prog-ragel')               # Find Ragel
subdir('meson/clock-gettime')            # Clock_gettime
subdir('meson/boost')                    # Boost
subdir('meson/boost-program-options')    # Boost Program Options Library
subdir('meson/unit-tests')               # Unit Tests
subdir('meson/reproducible')             # Reproducible Builds
subdir('meson/fuzz-targets')             # Fuzzing Targets
subdir('meson/python-venv')              # Python Venv
subdir('meson/from-git')                 # From Git
subdir('meson/dlopen')                   # dlopen
subdir('meson/verbose-logging')          # Verbose Logging
subdir('meson/pkcs11')                   # PKCS11
subdir('meson/gss-tsig')                 # GSS-TSIG
subdir('meson/auth-tools')               # Tools
subdir('meson/ixfrdist')                 # Ixfrdist

# Find or generate pdns/dnslabeltext.cc
if not ragel.found() and not fs.exists('pdns/dnslabeltext.cc')
  error('Ragel is missing and `pdns/dnslabeltext.cc` cannot be found. ' +
        'Install Ragel or download the sources from www.powerdns.com')
endif
# TODO Generate pdns/dnslabeltext.cc

# Backend Unit Tests
opt_backend_unittests = get_option('backend-unit-tests')
dep_boost_test = dependency('boost', modules: ['unit_test_framework'], required: opt_backend_unittests)
deps += dep_boost_test
conf.set10('BACKEND_UNIT_TESTS', opt_backend_unittests, description: 'Whether backend unit tests are enabled')
if not opt_unittests
  summary('Test', dep_boost_test.found(), bool_yn: true, section: 'Boost')
endif

# Swagger
if not fs.exists('pdns/api-swagger.json') and not python_have_venv
  error('Python3 and/or its venv module is not available and ' +
        '`pdns/api-swagger.json` cannot be found. ' +
        'The Authoritative Server cannot be built.')
endif
# TODO Generate api-swagger.json

# Manpages
if not fs.exists('docs/pdns_server.1') and not python_have_venv
  warning('Python3 and/or its venv module is not available and ' +
          '`docs/pdns_server.1` cannot be found. ' +
          'Documentation will not be built.')
endif
# TODO Generate pdns_server.1 manpage

# Various Functions
funcs = [
  'strcasestr',
  'localtime_r',
  'gmtime_r',
  'recvmmsg',
  'sched_setscheduler',
  'getrandom',
  'arc4random',
]
foreach func: funcs
  found = cxx.has_function(func)
  define = 'HAVE_' + func.to_upper()
  conf.set10(define, found, description: 'Whether we have ' + func)
  # summary(func, found, bool_yn: true, section: 'Various Functions')
endforeach

# Socket Dir
opt_socket_dir = get_option('socket-dir')

# Modules
all_modules = [
  ['bind',     []],
  ['pipe',     []],
  ['gmysql',   ['mysql']],
  ['godbc',    ['odbc']],
  ['gpgsql',   ['pgsql']],
  ['gsqlite3', ['sqlite3']],
  ['ldap',     ['ldap']],
  ['remote',   ['prog-curl', 'zeromq']],
  ['tinydns',  ['cdb']],
  ['geoip',    ['geoip']],
  ['lmdb',     ['lmdb', 'boost-serialization']],
]
selected_modules = []
selected_dyn_modules = []
foreach module: all_modules
  module_name = module[0]
  module_dir = module_name + 'backend'
  module_deps = module[1]
  module_opt = get_option('module-' + module_name)
  module_opt_dyn = get_option('module-' + module_name + '-dyn')

  if module_name == 'remote' and (module_opt != 'disabled' or module_opt_dyn != 'disabled')
    set_variable(module_name + '_module', module_opt != 'disabled')
    set_variable(module_name + '_dyn_module', module_opt_dyn != 'disabled')

    if module_opt != 'disabled'
      selected_modules += module_name
    endif

    if module_opt_dyn != 'disabled'
      selected_dyn_modules += module_name
    endif

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

    if module_opt
      selected_modules += module_name
    endif

    if module_opt_dyn
      selected_dyn_modules += module_name
    endif

    foreach dep: module_deps
      subdir('meson' / dep)
    endforeach
  else
    continue
  endif

  subdir('modules' / module_dir)
endforeach

conf.set_quoted('PDNS_MODULES', ' '.join(selected_modules), description: 'Built-in modules')
conf.set_quoted('PDNS_DYN_MODULES', ' '.join(selected_dyn_modules), description: 'Dynamically loadable modules that were built along with pdns')

# Generate config.h ----------------------------------------------------------------------
config_h = configure_file(configuration: conf, output: 'config.h')
# summary('Defines', conf.keys(), section: 'Build Configuration') # TODO Meson 0.57

# TODO: Add source files
auth = executable('pdns', config_h, dependencies: deps, export_dynamic: true)

# TODO Generate bindlexer.c and bindparser.cc.
# bindlexer_c = generator(flex, ...)
# bindparser_cc = generator(bison, ...)
