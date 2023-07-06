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

# Setup some modules
fs = import('fs')

# Create the configuration object and dependencies list.
conf = configuration_data()
deps = []

subdir('meson/compiler-setup')  # Common compiler setup (cxx is the C++ compiler)
subdir('meson/summary')         # Print a system/project summary
subdir('meson/timet-size')      # Check the size of time_t
subdir('meson/timet-sign')      # Check the sign of time_t
subdir('meson/flex-bison')      # Find flex and bison
subdir('meson/platform')        # Platform detection
subdir('meson/atomics')         # Check atomics support
subdir('meson/pthread-headers') # Check pthread headers
subdir('meson/pthread-setname') # Pthread setname madness
subdir('meson/strerror')        # Strerror_r
subdir('meson/lua')             # Lua
subdir('meson/hardening')       # Hardening
subdir('meson/kiss-rng')        # Unsafe KISS RNG
subdir('meson/net-libs')        # Network Libraries
subdir('meson/tm-gmtoff')       # Check for the tm_gmtoff field in struct tm
subdir('meson/mmap')            # Check for mmap
subdir('meson/libsodium')       # Libsodium-based signers
subdir('meson/libdecaf')        # Libdecaf-based signers
subdir('meson/libcrypto')       # OpenSSL-based signers
subdir('meson/libssl')          # OpenSSL libssl
subdir('meson/gnutls')          # GnuTLS
subdir('meson/dot')             # DNS over TLS
subdir('meson/ipcipher')        # IPCipher
subdir('meson/ragel')           # Find Ragel
subdir('meson/clock-gettime')   # Clock_gettime
subdir('meson/boost')           # Boost
subdir('meson/unit-tests')      # Unit Tests

# Boost Program Options library
dep_boost_program_options = dependency('boost', modules: ['program_options'], required: true)
summary('Boost Program Options', dep_boost_program_options.found(), bool_yn: true, section: 'Boost')

# Find or generate pdns/dnslabeltext.cc
if not ragel.found() and not fs.exists('pdns/dnslabeltext.cc')
  error('Ragel is missing and `pdns/dnslabeltext.cc` cannot be found. ' +
        'Install Ragel or download the sources from www.powerdns.com')
endif

# Generate config.h ----------------------------------------------------------------------
config_h = configure_file(configuration: conf, output: 'config.h')
# summary('Defines', conf.keys(), section: 'Build Configuration') # TODO Meson 0.57

# TODO: Add source files
auth = executable('pdns', config_h, dependencies: deps, export_dynamic: true)

# TODO Generate bindlexer.c and bindparser.cc.
# bindlexer_c = generator(flex, ...)
# bindparser_cc = generator(bison, ...)
