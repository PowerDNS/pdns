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

add_project_arguments('-DPDNS_AUTH', language: 'cpp')

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
subdir('meson' / 'net-libs')                # Network Libraries
subdir('meson' / 'tm-gmtoff')               # Check for tm_gmtoff field in struct tm
subdir('meson' / 'mmap')                    # Check for mmap
subdir('meson' / 'libsodium')               # Libsodium-based signers
subdir('meson' / 'libcrypto')               # OpenSSL-based signers
subdir('meson' / 'libssl')                  # OpenSSL libssl
subdir('meson' / 'libssl-engines')          # OpenSSL libssl engines
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
subdir('meson' / 'libsystemd')              # Systemd notification
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

common_sources = []

fs = import('fs')
src_dir = fs.is_dir('pdns') ? 'pdns' : ''
docs_dir = 'docs'
# Toplevel includes
dep_pdns = declare_dependency(include_directories: include_directories('.', src_dir))

# Ext
subdir('ext' / 'arc4random')
subdir('ext' / 'ipcrypt')
subdir('ext' / 'json11')
subdir('ext' / 'luawrapper')
subdir('ext' / 'protozero')
subdir('ext' / 'yahttp')

libpdns_gettime = declare_dependency(
  link_whole: static_library(
    'pdns-gettime',
    src_dir / 'gettime.cc',
    src_dir / 'gettime.hh',
    dependencies: dep_rt,
  )
)

libpdns_uuidutils = declare_dependency(
  link_whole: static_library(
    'pdns-uuidutils',
    src_dir / 'uuid-utils.cc',
    src_dir / 'uuid-utils.hh',
    dependencies: [dep_rt, dep_boost],
  )
)

if get_option('module-lmdb') != 'disabled'
  subdir('ext' / 'lmdb-safe')
endif

deps = [
  dep_pdns,
  dep_platform,
  dep_atomics,
  dep_threads,
  dep_lua,
  dep_lua_records,
  dep_netlibs,
  dep_libsodium,
  dep_libcrypto,
  dep_libssl,
  dep_gnutls,
  dep_boost,
  dep_boost_program_options,
  dep_dlopen,
  dep_pkcs11,
  dep_gss_tsig,
  dep_libsystemd,
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

if dep_systemd_prog.found()
  systemd_system_unit_dir = dep_systemd_prog.get_variable(
    'systemdsystemunitdir',
  )
  systemd_service_conf = configuration_data()
  systemd_service_conf.set('BinDir', get_option('prefix') / get_option('bindir'))
  systemd_service_conf.set('StaticBinDir', get_option('prefix') / get_option('sbindir'))
  systemd_service_user = get_option('systemd-service-user')
  systemd_service_group = get_option('systemd-service-group')
  systemd_service_conf.set('ServiceUser', systemd_service_user)
  systemd_service_conf.set('ServiceGroup', systemd_service_group)
  summary('Service User', systemd_service_user, section: 'Systemd')
  summary('Service Group', systemd_service_group, section: 'Systemd')

  # ProtectSystem=full will disallow write access to /etc and /usr, possibly not being
  # able to write slaved-zones into sqlite3 or zonefiles.
  systemd_service_conf.set(
    'ProtectSystem', have_systemd_protect_system ? 'ProtectSystem=full' : '',
  )
  systemd_service_conf.set(
    'SystemCallArchitectures',
    have_systemd_system_call_architectures ? 'SystemCallArchitectures=native' : '',
  )
  systemd_system_call_filter = '~ @clock @debug @module @mount @raw-io @reboot @swap @cpu-emulation @obsolete'
  systemd_service_conf.set(
    'SystemCallFilter',
    have_systemd_system_call_filter ? 'SystemCallFilter=' + systemd_system_call_filter : '',
  )
  systemd_service_conf.set(
    'ProtectProc',
    have_systemd_protect_proc ? 'ProtectProc=invisible' : '',
  )

  systemd_features = {
    'LockPersonality': have_systemd_lock_personality,
    'PrivateDevices': have_systemd_private_devices,
    'PrivateTmp': have_systemd_private_tmp,
    'PrivateUsers': false, # Setting it to true prevents us from opening our sockets.
    'ProtectClock': have_systemd_protect_clock,
    'ProtectControlGroups': have_systemd_protect_control_groups,
    'ProtectHome': have_systemd_protect_home,
    'ProtectHostname': have_systemd_protect_hostname,
    'ProtectKernelLogs': have_systemd_protect_kernel_logs,
    'ProtectKernelModules': have_systemd_protect_kernel_modules,
    'ProtectKernelTunables': have_systemd_protect_kernel_tunables,
    'RestrictNamespaces': have_systemd_restrict_namespaces,
    'RestrictRealtime': have_systemd_restrict_realtime,
    'RestrictSUIDSGID': have_systemd_restrict_suidsgid,
    'PrivateIPC': have_systemd_private_ipc,
    'RemoveIPC': have_systemd_remove_ipc,
  }

  foreach feature, enable_it: systemd_features
    systemd_service_conf.set(feature, enable_it ? feature + '=true': '')
  endforeach

  auth_service_conf = configuration_data()
  auth_service_conf.merge_from(systemd_service_conf)
  # Disabled, it breaks LuaJIT.
  auth_service_conf.set(
    'MemoryDenyWriteExecute',
    have_systemd_memory_deny_write_execute ? 'MemoryDenyWriteExecute=false' : '',
  )
  auth_service_conf.set(
    'RestrictAddressFamilies',
    have_systemd_restrict_address_families ? 'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6' : '',
  )

  enable_socket_dir = (not have_systemd_with_runtime_dir_env) and have_systemd_percent_t

  auth_service_conf_general = configuration_data()
  auth_service_conf_general.merge_from(auth_service_conf)
  auth_service_conf_general.set('Description', 'PowerDNS Authoritative Server')
  auth_service_conf_general.set('ConfigName', '')
  auth_service_conf_general.set('SocketDir', enable_socket_dir ? '--socket-dir=%t/pdns' : '')
  auth_service_conf_general.set('SyslogIdentifier', 'pdns_server')
  auth_service_conf_general.set('RuntimeDirectory', 'pdns')

  configure_file(
    input: 'pdns' / 'pdns.service.meson.in',
    output: 'pdns.service',
    configuration: auth_service_conf_general,
    install: true,
    install_dir: systemd_system_unit_dir,
  )

  auth_service_conf_instance = configuration_data()
  auth_service_conf_instance.merge_from(auth_service_conf)
  auth_service_conf_instance.set('Description', 'PowerDNS Authoritative Server %i')
  auth_service_conf_instance.set('ConfigName', '--config-name=%i')
  auth_service_conf_instance.set('SocketDir', enable_socket_dir ? '--socket-dir=%t/pdns-%i' : '')
  auth_service_conf_instance.set('SyslogIdentifier', 'pdns-%i')
  auth_service_conf_instance.set('RuntimeDirectory', have_systemd_percent_t ? 'pdns-%i' : 'pdns')

  configure_file(
    input: 'pdns' / 'pdns.service.meson.in',
    output: 'pdns@.service',
    configuration: auth_service_conf_instance,
    install: true,
    install_dir: systemd_system_unit_dir,
  )

  if get_option('tools-ixfrdist')
    ixfrdist_service_conf = configuration_data()
    ixfrdist_service_conf.merge_from(systemd_service_conf)
    ixfrdist_service_conf.set(
      'MemoryDenyWriteExecute',
      have_systemd_memory_deny_write_execute ? 'MemoryDenyWriteExecute=true' : '',
    )
    ixfrdist_service_conf.set(
      'RestrictAddressFamilies',
      have_systemd_restrict_address_families ? 'RestrictAddressFamilies=AF_INET AF_INET6' : '',
    )

    ixfrdist_service_conf_general = configuration_data()
    ixfrdist_service_conf_general.merge_from(ixfrdist_service_conf)
    ixfrdist_service_conf_general.set('Description', 'PowerDNS IXFR Distributor')
    ixfrdist_service_conf_general.set('Config', '')

    configure_file(
      input: 'pdns' / 'ixfrdist.service.meson.in',
      output: 'ixfrdist.service',
      configuration: ixfrdist_service_conf_general,
      install: true,
      install_dir: systemd_system_unit_dir,
    )

    ixfrdist_service_conf_instance = configuration_data()
    ixfrdist_service_conf_instance.merge_from(ixfrdist_service_conf)
    ixfrdist_service_conf_instance.set('Description', 'PowerDNS IXFR Distributor %i')
    ixfrdist_service_conf_instance.set('Config', '--config=' + get_option('sysconfdir') + '/ixfrdist-%i.yml')

    configure_file(
      input: 'pdns' / 'ixfrdist.service.meson.in',
      output: 'ixfrdist@.service',
      configuration: ixfrdist_service_conf_instance,
      install: true,
      install_dir: systemd_system_unit_dir,
    )
  endif
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

  summary('Ragel', ragel.found(), bool_yn: ragel.found(), section: 'DNS Labels')
  summary('Ragel Path', ragel.full_path(), section: 'DNS Labels')
  summary('Ragel Version', ragel.version(), section: 'DNS Labels')

  ragel_generator = generator(
    ragel,
    output: '@BASENAME@.cc',
    arguments: ['@INPUT@', '-o', '@OUTPUT@'],
  )

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
      dependencies: deps,
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
      dependencies: deps,
    )
  )
endif

libpdns_signers_openssl = declare_dependency(
  link_whole: static_library(
    'pdns-signers-openssl',
    sources: files(src_dir / 'opensslsigners.cc', src_dir / 'opensslsigners.hh'),
    dependencies: deps,
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
  src_dir / 'check-zone.cc',
  src_dir / 'check-zone.hh',
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

libpdns_bindparser = declare_dependency(
  link_with: static_library(
    'pdns-bindparser',
    libpdns_bindlexer_gen,
    libpdns_bindparser_gen,
    cpp_args: ['-Wno-redundant-decls', '-Wno-sign-compare'],
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

subdir('modules')

# Generate config.h
config_h = configure_file(configuration: conf, output: 'config.h')

tools = {
  'pdns_server': {
    'main': src_dir / 'auth-main.cc',
    'export-dynamic': true,
    'deps-extra': [
      dep_modules,
      libpdns_ssqlite3,
      libpdns_gettime,
      libpdns_signers_openssl,
      libpdns_signers_sodium,
    ],
    'manpages': ['pdns_server.1'],
    'install_dir': get_option('sbindir'),
  },
  'pdnsutil': {
    'main': src_dir / 'pdnsutil.cc',
    'export-dynamic': true,
    'files-extra': libpdns_bind_dnssec_schema_gen,
    'deps-extra': [
      dep_modules,
      libpdns_ssqlite3,
      libpdns_signers_openssl,
      libpdns_signers_sodium,
    ],
    'manpages': ['pdnsutil.1'],
  },
  'pdns_control': {
    'main': src_dir / 'dynloader.cc',
    'manpages': ['pdns_control.1'],
  },
  'zone2sql': {
    'main': src_dir / 'zone2sql.cc',
    'manpages': ['zone2sql.1'],
  },
  'zone2json': {
    'main': src_dir / 'zone2json.cc',
    'manpages': ['zone2json.1'],
  },
}

if get_option('module-ldap') != 'disabled'
  tools += {
    'zone2ldap': {
      'main': src_dir / 'zone2ldap.cc',
      'manpages': ['zone2ldap.1'],
    }
  }
endif

if get_option('tools')
  tools += {
    'pdns_notify': {
      'main': src_dir / 'notify.cc',
      'manpages': ['pdns_notify.1'],
    },
    'sdig': {
      'main': src_dir / 'sdig.cc',
      'deps-extra': dep_libcurl,
      'manpages': ['sdig.1'],
    },
    'calidns': {
      'main': src_dir / 'calidns.cc',
      'manpages': ['calidns.1'],
    },
    'dnsdemog': {
      'main': src_dir / 'dnsdemog.cc',
    },
    'dnsgram': {
      'main': src_dir / 'dnsgram.cc',
      'manpages': ['dnsgram.1'],
    },
    'dnspcap2calidns': {
      'main': src_dir / 'dnspcap2calidns.cc',
      'manpages': ['dnspcap2calidns.1'],
    },
    'dnspcap2protobuf' : {
      'main': src_dir / 'dnspcap2protobuf.cc',
      'deps-extra': libpdns_gettime,
      'manpages': ['dnspcap2protobuf.1'],
    },
    'dnsreplay': {
      'main': src_dir / 'dnsreplay.cc',
      'manpages': ['dnsreplay.1'],
    },
    'dnsscan'  : {
      'main': src_dir / 'dnsscan.cc',
      'manpages': ['dnsscan.1'],
    },
    'dnsscope' : {
      'main': src_dir / 'dnsscope.cc',
      'manpages': ['dnsscope.1'],
    },
    'dnswasher': {
      'main': src_dir / 'dnswasher.cc',
      'manpages': ['dnswasher.1'],
    },
    'nproxy'   : {
      'main': src_dir / 'nproxy.cc',
      'manpages': ['nproxy.1'],
    },
    'nsec3dig' : {
      'main': src_dir / 'nsec3dig.cc',
      'manpages': ['nsec3dig.1'],
    },
    'dumresp'  : {
      'main': src_dir / 'dumresp.cc',
      'manpages': ['dumresp.1'],
    },
    'kvresp'   : {
      'main': src_dir / 'kvresp.cc',
    },
    'stubquery': {
      'main': src_dir / 'stubquery.cc',
    },
    'saxfr'    : {
      'main': src_dir / 'saxfr.cc',
      'manpages': ['saxfr.1'],
    },
    'ixplore'  : {
      'main': src_dir / 'ixplore.cc',
      'manpages': ['ixplore.1'],
    },
    'dnstcpbench': {
      'main': src_dir / 'dnstcpbench.cc',
      'manpages': ['dnstcpbench.1'],
    },
    'dnsbulktest': {
      'main': src_dir / 'dnsbulktest.cc',
      'manpages': ['dnsbulktest.1'],
    },
    # Broken
    # 'comfun' : {
    #   'main': src_dir / 'comfun.cc',
    # },
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

endif

if get_option('tools-ixfrdist')
  tools += {
    'ixfrdist': {
      'main': src_dir / 'ixfrdist.cc',
      'manpages': [
        'ixfrdist.1',
        'ixfrdist.yml.5',
      ],
    },
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
      src_dir / 'test-dns_cc.cc',
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
    'pdns-auth-testrunner': {
      'main': src_dir / 'testrunner.cc',
      'deps-extra': [
        libpdns_test,
        libpdns_signers_openssl,
        libpdns_signers_sodium,
      ],
      'install': false,
    },
    'speedtest': {
      'main': src_dir / 'speedtest.cc',
      'install': false,
    },
    'tsig-tests': {
      'main': src_dir / 'tsig-tests.cc',
      'install': false,
    },
  }
endif

if get_option('fuzz-targets')
  fuzz_extra_sources = []
  fuzzer_ldflags = []
  # https://github.com/harfbuzz/harfbuzz/pull/2549/files
  if get_option('fuzzer_ldflags') == ''
    fuzz_extra_sources += src_dir / 'standalone_fuzz_target_runner.cc'
  else
    fuzzer_ldflags += get_option('fuzzer_ldflags')
  endif

  fuzz_targets = [
    'moadnsparser',
    'packetcache',
    'proxyprotocol',
    'dnslabeltext-parseRFC1035CharString',
    'yahttp',
    'zoneparsertng',
  ]

  foreach target: fuzz_targets
    source_file = src_dir / 'fuzz_' + target.underscorify() + '.cc'
    tools += {
      'fuzz-target-' + target: { 'main': source_file,
                                 'link-args': fuzzer_ldflags,
                                 'files-extra': fuzz_extra_sources,
                                 'install': false,
       }
    }
  endforeach
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

man_pages = []
foreach tool, info: tools
  var_name = tool.underscorify()
  main = files(info['main'])

  export_dynamic = 'export-dynamic' in info ? info['export-dynamic'] : false
  files_extra = 'files-extra' in info ? info['files-extra'] : []
  deps_extra = 'deps-extra' in info ? info['deps-extra'] : []
  link_args = 'link-args' in info ? info['link-args'] : []
  install = 'install' in info ? info['install'] : true
  install_dir = 'install_dir' in info ? info['install_dir'] : get_option('bindir')

  set_variable(
    var_name,
    executable(
      tool,
      main,
      config_h,
      files_extra,
      export_dynamic: export_dynamic,
      link_args: link_args,
      dependencies: [
        deps,
        libpdns_common,
        libpdns_uuidutils,
        deps_extra,
      ],
      install: install,
      install_dir: install_dir,
    )
  )

  if 'manpages' in info
    foreach man_page: info['manpages']
      man_pages += docs_dir / 'manpages' / (man_page + '.rst')
    endforeach
  endif
endforeach

dep_conf_distfile = custom_target(
  'gen-conf-distfile',
  command: [pdns_server, '--config=default'],
  output: 'pdns.conf-dist',
  capture: true,
  install: true,
  install_dir:  get_option('sysconfdir'),
)

if get_option('tools-ixfrdist')
  install_data(
    'pdns' / 'ixfrdist.example.yml',
    install_dir:  get_option('sysconfdir'),
  )
endif

# Man-pages.
py = import('python')
python = py.find_installation('python3', modules: 'venv', required: false)

summary('Python', python.found(), bool_yn: true, section: 'Manual Pages')
summary('Path', python.full_path(), section: 'Manual Pages')
summary('Version', python.version(), section: 'Manual Pages')

if python.found()
  generated_man_pages = []
  foreach tool, info: tools
    if 'manpages' in info
      foreach man_page: info['manpages']
        if not fs.is_file('docs' / man_page)
          generated_man_pages += man_page
        else
          install_man(
            'docs' / man_page,
            install_dir: man_page.endswith('.5') ? join_paths(get_option('mandir'), 'man5') : join_paths(get_option('mandir'), 'man1'),
          )
        endif
      endforeach
    endif
  endforeach
  if generated_man_pages.length() != 0
    summary('Generating man pages', true, section: 'Manual Pages')
    custom_target(
     'man-pages',
     input: man_pages,
     output: generated_man_pages,
     install: true,
     # wrong for ixfrdist.yml.5 but I don't know how to handle that
     install_dir: join_paths(get_option('mandir'), 'man1'),
     command: [
       python,
       product_source_dir / docs_dir / 'generate-man-pages.py',
       '--build-root', '@BUILD_ROOT@',
       '--source-root', '@SOURCE_ROOT@',
       '--venv-name', 'venv-auth-man-pages',
       '--requirements-file', docs_dir / 'requirements.txt',
       '--source-directory', docs_dir,
       '--target-directory', '@BUILD_ROOT@',
     ] + man_pages,
    )
  else
    summary('Generating man pages', false, section: 'Manual Pages')
  endif
endif

if get_option('unit-tests')
  test(
    'pdns-auth-testrunner',
    pdns_auth_testrunner,
    env: {
      'BOOST_TEST_LOG_LEVEL': 'message',
    },
    is_parallel: false,
  )
endif

if get_option('unit-tests-backends')
  socat = find_program('socat', required: true)
  # Remote Backend Tests #################################################################
  if get_option('module-remote') != 'disabled'
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
        env: env,
        workdir: product_source_dir / fs.parent(module_remotebackend_testrunner),
        is_parallel: false,
        depends: get_variable(exec_var_name),
      )
    endforeach
  endif

  # Regression Tests #####################################################################
  start_test_stop = files('regression-tests' / 'start-test-stop')[0]

  test_modules = {
    'geoip': 'module-geoip',
    'lmdb': 'module-lmdb',
    'lmdb-nodnssec': 'module-lmdb',
  }

  foreach module, option: test_modules
    if get_option(option) != 'disabled'
      test(
        'pdns-auth-backend-' + module,
        start_test_stop,
        env: {'PDNS_BUILD_PATH': meson.build_root()},
        args: ['5300', module],
        workdir: product_source_dir / 'regression-tests',
        depends: [pdns_server, pdnsutil, sdig, saxfr, pdns_notify, nsec3dig],
        is_parallel: false,
      )
    endif
  endforeach
endif

if python.found()
  html_docs = custom_target(
    'html-docs',
    command: [
        python,
        product_source_dir / docs_dir / 'generate-docs.py',
        '--build-root', '@BUILD_ROOT@',
        '--source-root', '@SOURCE_ROOT@',
        '--venv-name', 'venv-docs',
        '--requirements-file', docs_dir / 'requirements.txt',
        '--source-directory', docs_dir,
        '--target-directory', '@BUILD_ROOT@' / 'html-docs',
    ],
    output: 'sphinx.stamp',
    console: true,
    depfile: 'sphinx.d',
  )

  docs_tarball = custom_target(
    'html-docs.tar.bz2',
    command: ['tar', 'cjf', 'html-docs.tar.bz2', html_docs],
    output: 'html-docs.tar.bz2',
  )

  pdf_docs = custom_target(
    command: [
        python,
        product_source_dir / docs_dir / 'generate-docs.py',
        '--build-root', '@BUILD_ROOT@',
        '--source-root', '@SOURCE_ROOT@',
        '--venv-name', 'venv-docs',
        '--requirements-file', docs_dir / 'requirements.txt',
        '--source-directory', docs_dir,
        '--target-directory', '@BUILD_ROOT@',
        '--pdf-name', 'PowerDNS-Authoritative.pdf',
    ],
    output: 'PowerDNS-Authoritative.pdf',
    console: true,
    depfile: 'sphinx.d',
  )

  run_target(
    'all-docs',
    # args mentioned in command line become auto-dependency
    command: ['echo', 'Generated', html_docs, docs_tarball, pdf_docs],
  )
endif
