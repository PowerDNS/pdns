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

# Create the configuration object and dependencies list.
conf = configuration_data()

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
subdir('meson' / 'boost-test')              # Boost Testing Library
subdir('meson' / 'boost-serialization')     # Boost Serialization Library
subdir('meson' / 'reproducible')            # Reproducible Builds
subdir('meson' / 'dlopen')                  # dlopen
subdir('meson' / 'verbose-logging')         # Verbose Logging
subdir('meson' / 'pkcs11')                  # PKCS11
subdir('meson' / 'gss-tsig')                # GSS-TSIG
subdir('meson' / 'systemd')                 # Systemd and unit file handling
subdir('meson' / 'code-coverage')           # Code coverage
subdir('meson' / 'auto-var-init')           # Automatic Variable Initialization
subdir('meson' / 'sanitizers')              # Sanitizers
subdir('meson' / 'malloc-trace')            # Malloc-trace
subdir('meson' / 'socket-dir')              # Socket Dir
subdir('meson' / 'various-functions')       # Various Functions
subdir('meson' / 'various-headers')         # Various Headers
subdir('meson' / 'yaml-cpp')                # YAML C++
subdir('meson' / 'sqlite3')                 # Sqlite3
subdir('meson' / 'lmdb')                    # LMDB
subdir('meson' / 'mysql')                   # MySQL
subdir('meson' / 'odbc')                    # ODBC
subdir('meson' / 'pgsql')                   # PostgreSQL
subdir('meson' / 'ldap')                    # LDAP
subdir('meson' / 'prog-curl')               # cURL Program
subdir('meson' / 'zeromq')                  # ZeroMQ
subdir('meson' / 'cdb')                     # CDB
subdir('meson' / 'geoip')                   # GeoIP
subdir('meson' / 'mmdb')                    # MaxMindDB
subdir('meson' / 'cxx-fs')                  # C++ stdlib Filesystem Module

# Manpages
# if not fs.exists('docs' / 'pdns_server.1') and not python_have_venv
#   warning('Python3 and/or its venv module is not available and ' +
#           '`docs/pdns_server.1` cannot be found. ' +
#           'Documentation will not be built.')
# endif
# TODO Generate pdns_server.1 manpage

common_sources = []

fs = import('fs')
src_dir = fs.is_dir('pdns') ? 'pdns' : ''
# Toplevel includes
dep_pdns = declare_dependency(include_directories: include_directories('.', src_dir))

# Ext
subdir('ext' / 'arc4random')
subdir('ext' / 'ipcrypt')
subdir('ext' / 'json11')
subdir('ext' / 'luawrapper')
subdir('ext' / 'protozero')
subdir('ext' / 'yahttp')
if get_option('module-lmdb') != 'disabled'
  subdir('ext' / 'lmdb-safe')
endif

libpdns_bindlexer_source = src_dir / 'bindlexer.l'
libpdns_bindlexer_gen    = src_dir / 'bindlexer.c'
if not fs.is_file(libpdns_bindlexer_gen)
  flex = find_program('flex', required: true)

  summary('Flex', flex.found(), bool_yn: true, section: 'BIND Parser')
  summary('Flex Path', flex.full_path(), section: 'BIND Parser')
  summary('Flex Version', flex.version(), section: 'BIND Parser')

  flex_generator = generator(
    flex,
    output: '@BASENAME@.c',
    arguments: ['--case-insensitive', '--outfile=@OUTPUT@', '@INPUT@'],
  )

  libpdns_bindlexer_gen = flex_generator.process(libpdns_bindlexer_source)
endif

libpdns_bindparser_source     = src_dir / 'bindparser.yy'
libpdns_bindparser_gen        = src_dir / 'bindparser.cc'
libpdns_bindparser_gen_header = src_dir / 'bindparser.hh'
if not fs.is_file(libpdns_bindparser_gen) and not fs.is_file(libpdns_bindparser_gen_header)
  bison = find_program('bison', required: false)
  if not bison.found()
    bison = find_program('yacc', required: true)
  endif

  summary('Bison/YACC', bison.found(), bool_yn: true, section: 'BIND Parser')
  summary('Bison/YACC Path', bison.full_path(), section: 'BIND Parser')
  summary('Bison/YACC Version', bison.version(), section: 'BIND Parser')

  bison_generator = generator(
    bison,
    output: ['@BASENAME@.cc', '@BASENAME@.hh', '@BASENAME@.output'],
    arguments: ['-d', '--verbose', '--debug', '--output=@OUTPUT0@', '@INPUT@'],
  )

  libpdns_bindparser_gen = bison_generator.process(libpdns_bindparser_source)
endif

libpdns_dnslabeltext_source = src_dir / 'dnslabeltext.rl'
libpdns_dnslabeltext_gen    = src_dir / 'dnslabeltext.cc'
if not fs.is_file(libpdns_dnslabeltext_gen)
  ragel = find_program('ragel', required: true)
  ragel_generator = generator(
    ragel,
    output: '@BASENAME@.cc',
    arguments: ['@INPUT@', '-o', '@OUTPUT@'],
  )

  summary('Ragel', ragel.found(), bool_yn: ragel.found(), section: 'DNS Labels')
  summary('Ragel Path', ragel.full_path(), section: 'DNS Labels')
  summary('Ragel Version', ragel.version(), section: 'DNS Labels')

  libpdns_dnslabeltext_gen = ragel_generator.process(libpdns_dnslabeltext_source)
endif

libpdns_apidocfiles_source = 'docs' / 'http-api' / 'swagger' / 'authoritative-api-swagger.yaml'
libpdns_apidocfiles_gen    = src_dir / 'apidocfiles.h'
generate_api_swagger_py    = src_dir / 'generate-api-swagger.py'
if not fs.is_file(libpdns_apidocfiles_gen)
  py = import('python')
  python = py.find_installation('python3', modules: 'yaml', required: true)

  summary('Python', python.found(), bool_yn: true, section: 'Swagger API')
  summary('Path', python.full_path(), section: 'Swagger API')
  summary('Version', python.version(), section: 'Swagger API')

  libpdns_apidocfiles_gen = custom_target(
    'pdns-apidocfiles-h',
    command: [python, '@INPUT0@', '@INPUT1@'],
    input: [generate_api_swagger_py, libpdns_apidocfiles_source],
    output: 'apidocfiles.h',
    capture: true,
  )
endif

libpdns_bind_dnssec_schema_source = src_dir / 'bind-dnssec.schema.sqlite3.sql'
libpdns_bind_dnssec_schema_gen    = src_dir / 'bind-dnssec.schema.sqlite3.sql.h'
generate_bind_dnssec_schema_py    = src_dir / 'generate-bind-dnssec-schema.py'
if not fs.is_file(libpdns_bind_dnssec_schema_gen)
  py = import('python')
  python = py.find_installation('python3', required: true)

  summary('Python', python.found(), bool_yn: true, section: 'BIND DNSSEC Schema')
  summary('Path', python.full_path(), section: 'BIND DNSSEC Schema')
  summary('Version', python.version(), section: 'BIND DNSSEC Schema')

  libpdns_bind_dnssec_schema_gen = custom_target(
    'pdns-bind-dnssec-schema',
    command: [python, '@INPUT0@', '@INPUT1@'],
    input: [generate_bind_dnssec_schema_py, libpdns_bind_dnssec_schema_source],
    output: 'bind-dnssec.schema.sqlite3.sql.h',
    capture: true,
  )
endif

conditional_sources = {
  'mplexer-sunos-devpoll': {
    'sources': [
      src_dir / 'devpollmplexer.cc',
      src_dir / 'portsmplexer.cc',
    ],
    'condition': have_sunos,
  },
  'mplexer-linux-epoll': {
    'sources': [src_dir / 'epollmplexer.cc'],
    'condition': have_linux,
  },
  'mplexer-bsd-kqueue': {
    'sources': [src_dir / 'kqueuemplexer.cc'],
    'condition': have_openbsd or have_freebsd,
  },
  'minicurl': {
    'sources': [
      src_dir / 'minicurl.cc',
      src_dir / 'minicurl.hh',
    ],
    'condition': dep_lua_records.found() or dep_libcurl.found(),
  },
  'lua-record': {
    'sources': [src_dir / 'lua-record.cc'],
    'condition': dep_lua_records.found(),
  },
  'standalone-fuzz-target-runner': {
    'sources': [src_dir / 'standalone_fuzz_target_runner.cc'],
    'condition': get_option('fuzz-targets'),
  },
}

foreach name, info: conditional_sources
  if info['condition']
    common_sources += files(info['sources'])
  endif
endforeach

# Conditional sources that need to be separated into standalone libraries for special
# linking without implicitly getting rid of symbols.
libpdns_signers_sodium = dependency('', required: false)
if dep_libsodium.found()
  libpdns_signers_sodium = declare_dependency(
    link_whole: static_library(
      'pdns-signers-sodium',
      sources: files(src_dir / 'sodiumsigners.cc'),
      dependencies: dep_libsodium,
    )
  )
endif

libpdns_signers_decaf = dependency('', required: false)
if dep_libdecaf.found()
  libpdns_signers_decaf = declare_dependency(
    link_whole: static_library(
      'pdns-signers-decaf',
      sources: files(src_dir / 'decafsigners.cc'),
      dependencies: dep_libdecaf,
    )
  )
endif

libpdns_signers_pkcs11 = dependency('', required: false)
if dep_pkcs11.found()
  libpdns_signers_pkcs11 = declare_dependency(
    link_whole: static_library(
      'pdns-signers-pkcs11',
      sources: files(src_dir / 'pkcs11signers.cc', src_dir / 'pkcs11signers.hh'),
      dependencies: dep_pkcs11,
    )
  )
endif

# This needs to be link_whole'd because it's needed by auth backends.
libpdns_ssqlite3 = dependency('', required: false)
if dep_sqlite3.found()
  libpdns_ssqlite3 = declare_dependency(
    link_whole: static_library(
      'pdns-ssqlite3',
      sources: files(src_dir / 'ssqlite3.cc', src_dir / 'ssqlite3.hh'),
      dependencies: dep_sqlite3,
    )
  )
endif

libpdns_gettime = declare_dependency(
  link_whole: static_library(
    'pdns-gettime',
    src_dir / 'gettime.cc',
    src_dir / 'gettime.hh',
    dependencies: dep_rt,
  )
)

libpdns_signers_openssl = declare_dependency(
  link_whole: static_library(
    'pdns-signers-openssl',
    sources: files(src_dir / 'opensslsigners.cc', src_dir / 'opensslsigners.hh'),
    dependencies: dep_libcrypto,
  )
)

common_sources += files(
  src_dir / 'arguments.cc',
  src_dir / 'arguments.hh',
  src_dir / 'auth-caches.cc',
  src_dir / 'auth-caches.hh',
  src_dir / 'auth-carbon.cc',
  src_dir / 'auth-catalogzone.cc',
  src_dir / 'auth-catalogzone.hh',
  src_dir / 'auth-main.hh',
  src_dir / 'auth-packetcache.cc',
  src_dir / 'auth-packetcache.hh',
  src_dir / 'auth-primarycommunicator.cc',
  src_dir / 'auth-querycache.cc',
  src_dir / 'auth-querycache.hh',
  src_dir / 'auth-secondarycommunicator.cc',
  src_dir / 'auth-zonecache.cc',
  src_dir / 'auth-zonecache.hh',
  src_dir / 'axfr-retriever.cc',
  src_dir / 'axfr-retriever.hh',
  src_dir / 'backends' / 'gsql' / 'gsqlbackend.cc', # TODO Move to a separate module.
  src_dir / 'backends' / 'gsql' / 'gsqlbackend.hh', # TODO Move to a separate module.
  src_dir / 'backends' / 'gsql' / 'ssql.hh',        # TODO Move to a separate module.
  src_dir / 'base32.cc',
  src_dir / 'base32.hh',
  src_dir / 'base64.cc',
  src_dir / 'base64.hh',
  src_dir / 'bindparserclasses.hh',
  src_dir / 'burtle.hh',
  src_dir / 'cachecleaner.hh',
  src_dir / 'circular_buffer.hh',
  src_dir / 'comment.hh',
  src_dir / 'communicator.cc',
  src_dir / 'communicator.hh',
  src_dir / 'coverage.cc',
  src_dir / 'coverage.hh',
  src_dir / 'credentials.cc',
  src_dir / 'credentials.hh',
  src_dir / 'dbdnsseckeeper.cc',
  src_dir / 'digests.hh',
  src_dir / 'distributor.hh',
  src_dir / 'dns.cc',
  src_dir / 'dns.hh',
  src_dir / 'dns_random.hh',
  src_dir / 'dnsbackend.cc',
  src_dir / 'dnsbackend.hh',
  src_dir / 'dnsname.cc',
  src_dir / 'dnsname.hh',
  src_dir / 'dnspacket.cc',
  src_dir / 'dnspacket.hh',
  src_dir / 'dnsparser.cc',
  src_dir / 'dnsparser.hh',
  src_dir / 'dnsproxy.cc',
  src_dir / 'dnsproxy.hh',
  src_dir / 'dnsrecords.cc',
  src_dir / 'dnsrecords.hh',
  src_dir / 'dnssecinfra.cc',
  src_dir / 'dnssecinfra.hh',
  src_dir / 'dnsseckeeper.hh',
  src_dir / 'dnssecsigner.cc',
  src_dir / 'dnswriter.cc',
  src_dir / 'dnswriter.hh',
  src_dir / 'dynhandler.cc',
  src_dir / 'dynhandler.hh',
  src_dir / 'dynlistener.cc',
  src_dir / 'dynlistener.hh',
  src_dir / 'dynmessenger.cc',
  src_dir / 'dynmessenger.hh',
  src_dir / 'ednscookies.cc',
  src_dir / 'ednscookies.hh',
  src_dir / 'ednsoptions.cc',
  src_dir / 'ednsoptions.hh',
  src_dir / 'ednssubnet.cc',
  src_dir / 'ednssubnet.hh',
  src_dir / 'gss_context.cc',
  src_dir / 'gss_context.hh',
  src_dir / 'histogram.hh',
  src_dir / 'ipcipher.cc',
  src_dir / 'ipcipher.hh',
  src_dir / 'iputils.cc',
  src_dir / 'iputils.hh',
  src_dir / 'ixfr.cc',
  src_dir / 'ixfr.hh',
  src_dir / 'json.cc',
  src_dir / 'json.hh',
  src_dir / 'lock.hh',
  src_dir / 'logger.cc',
  src_dir / 'logger.hh',
  src_dir / 'logging.hh',
  src_dir / 'lua-auth4.cc',
  src_dir / 'lua-auth4.hh',
  src_dir / 'lua-base4.cc',
  src_dir / 'lua-base4.hh',
  src_dir / 'misc.cc',
  src_dir / 'misc.hh',
  src_dir / 'nameserver.cc',
  src_dir / 'nameserver.hh',
  src_dir / 'namespaces.hh',
  src_dir / 'noinitvector.hh',
  src_dir / 'nsecrecords.cc',
  src_dir / 'packetcache.hh',
  src_dir / 'packethandler.cc',
  src_dir / 'packethandler.hh',
  src_dir / 'pdnsexception.hh',
  src_dir / 'proxy-protocol.cc',
  src_dir / 'proxy-protocol.hh',
  src_dir / 'qtype.cc',
  src_dir / 'qtype.hh',
  src_dir / 'query-local-address.cc',
  src_dir / 'query-local-address.hh',
  src_dir / 'rcpgenerator.cc',
  src_dir / 'rcpgenerator.hh',
  src_dir / 'resolver.cc',
  src_dir / 'resolver.hh',
  src_dir / 'responsestats-auth.cc',
  src_dir / 'responsestats.cc',
  src_dir / 'responsestats.hh',
  src_dir / 'rfc2136handler.cc',
  src_dir / 'secpoll-auth.cc',
  src_dir / 'secpoll-auth.hh',
  src_dir / 'secpoll.cc',
  src_dir / 'secpoll.hh',
  src_dir / 'serialtweaker.cc',
  src_dir / 'sha.hh',
  src_dir / 'shuffle.cc',
  src_dir / 'shuffle.hh',
  src_dir / 'signingpipe.cc',
  src_dir / 'signingpipe.hh',
  src_dir / 'sillyrecords.cc',
  src_dir / 'sstuff.hh',
  src_dir / 'stat_t.hh',
  src_dir / 'statbag.cc',
  src_dir / 'statbag.hh',
  src_dir / 'stubresolver.cc',
  src_dir / 'stubresolver.hh',
  src_dir / 'svc-records.cc',
  src_dir / 'svc-records.hh',
  src_dir / 'tcpreceiver.cc',
  src_dir / 'tcpreceiver.hh',
  src_dir / 'threadname.cc',
  src_dir / 'threadname.hh',
  src_dir / 'tkey.cc',
  src_dir / 'trusted-notification-proxy.cc',
  src_dir / 'trusted-notification-proxy.hh',
  src_dir / 'tsigutils.cc',
  src_dir / 'tsigutils.hh',
  src_dir / 'tsigverifier.cc',
  src_dir / 'tsigverifier.hh',
  src_dir / 'ueberbackend.cc',
  src_dir / 'ueberbackend.hh',
  src_dir / 'unix_semaphore.cc',
  src_dir / 'unix_utility.cc',
  src_dir / 'utility.hh',
  src_dir / 'uuid-utils.cc',
  src_dir / 'uuid-utils.hh',
  src_dir / 'validate.hh',
  src_dir / 'version.cc',
  src_dir / 'version.hh',
  src_dir / 'webserver.cc',
  src_dir / 'webserver.hh',
  src_dir / 'ws-api.cc',
  src_dir / 'ws-api.hh',
  src_dir / 'ws-auth.cc',
  src_dir / 'ws-auth.hh',
  src_dir / 'zonemd.cc',
  src_dir / 'zonemd.hh',
  src_dir / 'zoneparser-tng.cc',
  src_dir / 'zoneparser-tng.hh',
)

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
  dep_boost,
  dep_boost_program_options,
  dep_dlopen,
  dep_pkcs11,
  dep_gss_tsig,
  dep_systemd,
  dep_arc4random,
  dep_ipcrypt,
  dep_json11,
  dep_luawrapper,
  dep_protozero,
  dep_yahttp,
  dep_yaml_cpp,
  dep_sqlite3,
  dep_lmdb,
  dep_boost_serialization,
  dep_mysql,
  dep_odbc,
  dep_pgsql,
  dep_ldap,
  dep_cdb,
  dep_geoip,
  dep_mmdb,
  dep_cxx_fs,
  dep_boost_test,
]

libpdns_bindparser = declare_dependency(
  link_with: static_library(
    'pdns-bindparser',
    libpdns_bindlexer_gen,
    libpdns_bindparser_gen,
    cpp_args: '-Wno-redundant-decls',
    dependencies: deps,
  )
)

libpdns_dnslabeltext = declare_dependency(
  link_with: static_library(
    'pdns-dnslabeltext',
    libpdns_dnslabeltext_gen,
    dependencies: deps,
  )
)

libpdns_cdb = dependency('', required: false)
if dep_cdb.found()
  libpdns_cdb = declare_dependency(
    link_whole: static_library(
      'pdns-cdb',
      sources: files(src_dir / 'cdb.cc', src_dir / 'cdb.hh'),
      dependencies: deps,
    )
  )
endif

# Modules
all_modules = [
  'bind',
  'pipe',
  'gmysql',
  'godbc',
  'gpgsql',
  'gsqlite3',
  'ldap',
  'lua2',
  'remote',
  'tinydns',
  'geoip',
  'lmdb',
]

selected_modules = []
selected_dyn_modules = []
dep_modules = []
foreach module_name: all_modules
  module_backend_name = module_name + 'backend'
  module_opt = get_option('module-' + module_name)

  if module_opt == 'disabled'
    continue
  elif module_opt == 'static'
    selected_modules += module_name
  else
    selected_dyn_modules += module_name
  endif

  subdir('modules' / module_backend_name)
  dep_modules += get_variable('dep_' + module_backend_name)
endforeach

conf.set_quoted('PDNS_MODULES', ' '.join(selected_modules), description: 'Built-in modules')
conf.set_quoted('PDNS_DYN_MODULES', ' '.join(selected_dyn_modules), description: 'Loadable modules')

# Generate config.h
config_h = configure_file(configuration: conf, output: 'config.h')

tools = {
  'pdns-auth' : {
    'main': src_dir / 'auth-main.cc',
    'export-dynamic': true,
    'deps-extra': [
      dep_modules,
      libpdns_ssqlite3,
      libpdns_gettime,
      libpdns_signers_openssl,
      libpdns_signers_decaf,
      libpdns_signers_sodium,
    ],
  },

  'pdns-auth-util'    : {
    'main': src_dir / 'pdnsutil.cc',
    'files-extra': libpdns_bind_dnssec_schema_gen,
    'deps-extra': [
      libpdns_ssqlite3,
      libpdns_signers_openssl,
      libpdns_signers_decaf,
      libpdns_signers_sodium,
    ],
  },
  'pdns-auth-control' : { 'main': src_dir / 'dynloader.cc' },
  'pdns-zone2sql'     : { 'main': src_dir / 'zone2sql.cc'  },
  'pdns-zone2json'    : { 'main': src_dir / 'zone2json.cc' },
}

if get_option('module-ldap') != 'disabled'
  tools += { 'pdns-zone2ldap' : { 'main': src_dir / 'zone2ldap.cc' } }
endif

if get_option('tools')
  tools += {
    'pdns-auth-notify' : { 'main': src_dir / 'notify.cc'           },
    'sdig'             : { 'main': src_dir / 'sdig.cc'             },
    'calidns'          : { 'main': src_dir / 'calidns.cc'          },
    'dnsdemog'         : { 'main': src_dir / 'dnsdemog.cc'         },
    'dnsgram'          : { 'main': src_dir / 'dnsgram.cc'          },
    'dnspcap2calidns'  : { 'main': src_dir / 'dnspcap2calidns.cc'  },
    'dnspcap2protobuf' : {
      'main': src_dir / 'dnspcap2protobuf.cc',
      'deps-extra': libpdns_gettime,
    },
    'dnsreplay'        : { 'main': src_dir / 'dnsreplay.cc'        },
    'dnsscan'          : { 'main': src_dir / 'dnsscan.cc'          },
    'dnsscope'         : { 'main': src_dir / 'dnsscope.cc'         },
    'dnswasher'        : { 'main': src_dir / 'dnswasher.cc'        },
    'nproxy'           : { 'main': src_dir / 'nproxy.cc'           },
    'nsec3dig'         : { 'main': src_dir / 'nsec3dig.cc'         },
    'dumresp'          : { 'main': src_dir / 'dumresp.cc'          },
    'kvresp'           : { 'main': src_dir / 'kvresp.cc'           },
    'stubquery'        : { 'main': src_dir / 'stubquery.cc'        },
    'saxfr'            : { 'main': src_dir / 'saxfr.cc'            },
    'ixplore'          : { 'main': src_dir / 'ixplore.cc'          },
    # 'comfun'         : { 'main': src_dir / 'comfun.cc'           }, # Broken
  }

  common_sources += files(
    src_dir / 'anadns.hh',
    src_dir / 'dnspcap.cc',
    src_dir / 'dnspcap.hh',
    src_dir / 'dolog.hh',
    src_dir / 'ednsextendederror.cc',
    src_dir / 'ednsextendederror.hh',
    src_dir / 'histog.hh',
    src_dir / 'ixfrutils.cc',
    src_dir / 'ixfrutils.hh',
    src_dir / 'libssl.cc',
    src_dir / 'libssl.hh',
    src_dir / 'mplexer.hh',
    src_dir / 'pollmplexer.cc',
    src_dir / 'protozero.cc',
    src_dir / 'protozero.hh',
    src_dir / 'statnode.cc',
    src_dir / 'statnode.hh',
    src_dir / 'tcpiohandler.cc',
    src_dir / 'tcpiohandler.hh',
  )

  if have_boost_1_48_0
    tools += {
      'dnstcpbench': { 'main': src_dir / 'dnstcpbench.cc' },
      'dnsbulktest': { 'main': src_dir / 'dnsbulktest.cc' },
    }
  endif
endif

if get_option('tools-ixfrdist')
  tools += {
    'ixfrdist': {'main': src_dir / 'ixfrdist.cc' },
  }

  common_sources += files(
    src_dir / 'ixfrdist-stats.cc',
    src_dir / 'ixfrdist-stats.hh',
    src_dir / 'ixfrdist-web.cc',
    src_dir / 'ixfrdist-web.hh',
    src_dir / 'ixfrutils.cc',
    src_dir / 'ixfrutils.hh',
    src_dir / 'mplexer.hh',
    src_dir / 'pollmplexer.cc',
  )
endif

if get_option('unit-tests')
  libpdns_test = declare_dependency(
    link_whole: static_library(
      'pdns-test',
      config_h,
      src_dir / 'channel.cc',
      src_dir / 'channel.hh',
      src_dir / 'pollmplexer.cc',
      src_dir / 'test-arguments_cc.cc',
      src_dir / 'test-auth-zonecache_cc.cc',
      src_dir / 'test-base32_cc.cc',
      src_dir / 'test-base64_cc.cc',
      src_dir / 'test-bindparser_cc.cc',
      src_dir / 'test-channel.cc',
      src_dir / 'test-common.hh',
      src_dir / 'test-communicator_hh.cc',
      src_dir / 'test-credentials_cc.cc',
      src_dir / 'test-digests_hh.cc',
      src_dir / 'test-distributor_hh.cc',
      src_dir / 'test-dns_random_hh.cc',
      src_dir / 'test-dnsname_cc.cc',
      src_dir / 'test-dnsparser_cc.cc',
      src_dir / 'test-dnsparser_hh.cc',
      src_dir / 'test-dnsrecordcontent.cc',
      src_dir / 'test-dnsrecords_cc.cc',
      src_dir / 'test-dnswriter_cc.cc',
      src_dir / 'test-ednscookie_cc.cc',
      src_dir / 'test-ipcrypt_cc.cc',
      src_dir / 'test-iputils_hh.cc',
      src_dir / 'test-ixfr_cc.cc',
      src_dir / 'test-lock_hh.cc',
      src_dir / 'test-lua_auth4_cc.cc',
      src_dir / 'test-luawrapper.cc',
      src_dir / 'test-misc_hh.cc',
      src_dir / 'test-mplexer.cc',
      src_dir / 'test-nameserver_cc.cc',
      src_dir / 'test-packetcache_cc.cc',
      src_dir / 'test-packetcache_hh.cc',
      src_dir / 'test-proxy_protocol_cc.cc',
      src_dir / 'test-rcpgenerator_cc.cc',
      src_dir / 'test-sha_hh.cc',
      src_dir / 'test-signers.cc',
      src_dir / 'test-statbag_cc.cc',
      src_dir / 'test-svc_records_cc.cc',
      src_dir / 'test-trusted-notification-proxy_cc.cc',
      src_dir / 'test-tsig.cc',
      src_dir / 'test-ueberbackend_cc.cc',
      src_dir / 'test-webserver_cc.cc',
      src_dir / 'test-zonemd_cc.cc',
      src_dir / 'test-zoneparser_tng_cc.cc',
      src_dir / 'zoneparser-tng.hh',
      dependencies: [
        deps,
      ],
    )
  )

  tools += {
    # TODO: NOINSTALL speedtest and pdns-auth-testrunner
    'pdns-auth-testrunner': {
      'main': src_dir / 'testrunner.cc',
      'deps-extra': [
        libpdns_test,
        libpdns_signers_openssl,
        libpdns_signers_decaf,
        libpdns_signers_sodium,
      ],
    },
    'speedtest'           : { 'main': src_dir / 'speedtest.cc'  },
    'tsig-tests'          : { 'main': src_dir / 'tsig-tests.cc' },
  }
endif

if get_option('fuzz-targets')
  tools += {
    'fuzz-target-moadnsparser'                        : { 'main': src_dir / 'fuzz_moadnsparser.cc'                        },
    'fuzz-target-packetcache'                         : { 'main': src_dir / 'fuzz_packetcache.cc'                         },
    'fuzz-target-proxyprotocol'                       : { 'main': src_dir / 'fuzz_proxyprotocol.cc'                       },
    'fuzz-target-dnslabeltext-parseRFC1035CharString' : { 'main': src_dir / 'fuzz_dnslabeltext_parseRFC1035CharString.cc' },
    'fuzz-target-yahttp'                              : { 'main': src_dir / 'fuzz_yahttp.cc'                              },
    'fuzz-target-zoneparsertng'                       : { 'main': src_dir / 'fuzz_zoneparsertng.cc'                       },
  }
endif

libpdns_common = declare_dependency(
  link_with: static_library(
    'pdns-common',
    common_sources,
    config_h,
    libpdns_apidocfiles_gen,
    dependencies: [
      deps,
      libpdns_signers_pkcs11,
      libpdns_bindparser,
      libpdns_dnslabeltext,
    ],
  )
)

foreach tool, info: tools
  var_name = tool.underscorify()
  main = files(info['main'])

  export_dynamic = 'export-dynamic' in info ? info['export-dynamic'] : false
  files_extra = 'files-extra' in info ? info['files-extra'] : []
  deps_extra = 'deps-extra' in info ? info['deps-extra'] : []

  set_variable(
    var_name,
    executable(
      tool,
      main,
      config_h,
      files_extra,
      export_dynamic: export_dynamic,
      dependencies: [
        deps,
        libpdns_common,
        deps_extra,
      ],
    )
  )
endforeach

if get_option('unit-tests')
  test(
    'pdns-auth-testrunner',
    pdns_auth_testrunner,
    verbose: get_option('unit-tests-verbose'),
    env: {
      'BOOST_TEST_LOG_LEVEL': 'message',
    },
    is_parallel: false,
  )
endif

if get_option('unit-tests-backends')
  libpdns_module_remotebackend_test_common = declare_dependency(
    link_whole: static_library(
      'pdns-test-remotebackend',
      module_remotebackend_test_sources_common,
      dependencies: [
        deps,
        module_remotebackend_lib,
        libpdns_signers_pkcs11,
        libpdns_common,
        libpdns_dnslabeltext,
      ],
      extra_files: module_remotebackend_test_sources_extra,
    )
  )

  env = {
    'BOOST_TEST_LOG_LEVEL': 'message',
    'REMOTEBACKEND_ZEROMQ': get_option('module-remote-zeromq') ? 'yes' : 'no',
  }

  verbose = get_option('unit-tests-verbose')

  foreach test_binary, test_source: module_remotebackend_test_sources_binaries
    exec_var_name = test_binary.underscorify()

    set_variable(
      exec_var_name,
      executable(
        test_binary,
        test_source,
        dependencies: [
          deps,
          dep_boost_test,
          dep_zeromq,
          libpdns_module_remotebackend_test_common,
        ],
      )
    )

    test(
      'pdns-auth-' + test_binary,
      module_remotebackend_testrunner,
      args: ['--', get_variable(exec_var_name).full_path()],
      verbose: verbose,
      env: env,
      workdir: product_source_dir / fs.parent(module_remotebackend_testrunner),
      is_parallel: false,
    )
  endforeach
endif
