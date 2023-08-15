libpdns_bindparser = declare_dependency(
  link_with: static_library(
    'pdns-bindparser',
    'zoneparser-tng.cc',
    'zoneparser-tng.hh',
    flex_generator.process('bindlexer.l'),
    bison_generator.process('bindparser.yy'),
    include_directories: toplevel_includes,
    cpp_args: '-Wno-redundant-decls',
  )
)

libpdns_lua = dependency('', required: false)
if dep_lua.found()
  libpdns_lua = declare_dependency(
    sources: [
      'lua-base4.cc',
      'lua-base4.hh',
    ],
    dependencies: dep_lua,
  )
endif

libpdns_lua_records = dependency('', required: false)
if opt_lua_records
  libpdns_lua_records = static_library(
    'libpdns-lua-records',
    'lua-record.cc',
    'minicurl.cc',
    'minicurl.hh',
    include_directories: toplevel_includes,
    dependencies: [dep_lua, dep_libcurl],
  )

  libpdns_lua_records = declare_dependency(
    link_with: libpdns_lua_records,
  )
endif

libpdns_tsig = dependency('', required: false)
if dep_gss_tsig.found()
  libpdns_tsig = static_library(
    'libpdns-tsig',
    'tsigutils.cc',
    'tsigutils.hh',
    'tsigverifier.cc',
    'tsigverifier.hh',
    'gss_context.cc',
    'gss_context.hh',
    cpp_args: '-Wno-redundant-decls',
    include_directories: toplevel_includes,
    dependencies: dep_gss_tsig,
  )

  libpdns_tsig = declare_dependency(
    link_with: libpdns_tsig,
  )
endif

libpdns_ws = declare_dependency(
  link_with: static_library(
    'libpdns-ws',
    'webserver.cc',
    'webserver.hh',
    'ws-api.cc',
    'ws-api.hh',
    cpp_args: '-Wno-overloaded-virtual',
    include_directories: toplevel_includes,
    dependencies: [dep_yahttp, dep_json11],
  )
)

libpdns = static_library(
  'pdns',
  'arguments.cc',
  'arguments.hh',
  'axfr-retriever.cc',
  'axfr-retriever.hh',
  'backends/gsql/gsqlbackend.cc',
  'backends/gsql/gsqlbackend.hh',
  'backends/gsql/ssql.hh',
  'base32.cc',
  'base32.hh',
  'base64.cc',
  'base64.hh',
  'bind-dnssec.schema.sqlite3.sql.h',
  'burtle.hh',
  'cachecleaner.hh',
  'circular_buffer.hh',
  'comment.hh',
  'communicator.cc',
  'communicator.hh',
  'credentials.cc',
  'credentials.hh',
  'dbdnsseckeeper.cc',
  'digests.hh',
  'distributor.hh',
  'dns.cc',
  'dns.hh',
  'dns_random.hh',
  'dnsbackend.cc',
  'dnsbackend.hh',
  'dnsname.cc',
  'dnsname.hh',
  'dnspacket.cc',
  'dnspacket.hh',
  'dnsparser.cc',
  'dnsparser.hh',
  'dnsproxy.cc',
  'dnsproxy.hh',
  'dnsrecords.cc',
  'dnsrecords.hh',
  'dnssecinfra.cc',
  'dnssecinfra.hh',
  'dnsseckeeper.hh',
  'dnssecsigner.cc',
  'dnswriter.cc',
  'dnswriter.hh',
  'dynhandler.cc',
  'dynhandler.hh',
  'dynlistener.cc',
  'dynlistener.hh',
  'dynmessenger.hh',
  'ednscookies.cc',
  'ednscookies.hh',
  'ednsoptions.cc',
  'ednsoptions.hh',
  'ednssubnet.cc',
  'ednssubnet.hh',
  'gettime.cc',
  'gettime.hh',
  'histogram.hh',
  'iputils.cc',
  'iputils.hh',
  'ixfr.cc',
  'ixfr.hh',
  'json.cc',
  'json.hh',
  'lock.hh',
  'logger.cc',
  'logger.hh',
  'logging.hh',
  'mastercommunicator.cc',
  'misc.cc',
  'misc.hh',
  'nameserver.cc',
  'nameserver.hh',
  'namespaces.hh',
  'noinitvector.hh',
  'nsecrecords.cc',
  'nsecrecords.cc',
  'opensslsigners.cc',
  'opensslsigners.hh',
  'packetcache.hh',
  'packethandler.cc',
  'packethandler.hh',
  'pdnsexception.hh',
  'proxy-protocol.cc',
  'proxy-protocol.hh',
  'qtype.cc',
  'qtype.hh',
  'query-local-address.cc',
  'query-local-address.hh',
  'rcpgenerator.cc',
  'rcpgenerator.hh',
  'resolver.cc',
  'resolver.hh',
  'responsestats.cc',
  'responsestats.hh',
  'rfc2136handler.cc',
  'secpoll.cc',
  'secpoll.hh',
  'serialtweaker.cc',
  'sha.hh',
  'shuffle.cc',
  'shuffle.hh',
  'signingpipe.cc',
  'signingpipe.hh',
  'sillyrecords.cc',
  'sillyrecords.cc',
  'slavecommunicator.cc',
  'stat_t.hh',
  'statbag.cc',
  'statbag.hh',
  'stubresolver.cc',
  'stubresolver.hh',
  'svc-records.cc',
  'svc-records.hh',
  'tcpreceiver.cc',
  'tcpreceiver.hh',
  'threadname.cc',
  'threadname.hh',
  'tkey.cc',
  'trusted-notification-proxy.cc',
  'trusted-notification-proxy.hh',
  'ueberbackend.cc',
  'ueberbackend.hh',
  'unix_semaphore.cc',
  'unix_utility.cc',
  'unix_utility.cc',
  'utility.hh',
  'utility.hh',
  'uuid-utils.cc',
  'uuid-utils.hh',
  'version.cc',
  'version.hh',
  'zoneparser-tng.cc',
  ragel_generator.process('dnslabeltext.rl'),
  include_directories: toplevel_includes,
  dependencies: [
    dep_pkcs11,
    dep_gss_tsig,
    dep_json11,
    dep_yahttp,
    libpdns_bindparser,
    libpdns_lua,
    libpdns_lua_records,
    libpdns_tsig,
    libpdns_ws,
  ],
)

libpdns_auth_main = declare_dependency(
  link_with: static_library(
    'pdns-auth-main',
    'auth-main.cc',
    'auth-main.hh',
    cpp_args: '-Wno-overloaded-virtual',
    include_directories: toplevel_includes,
    dependencies: [
      dep_yahttp,
      dep_json11,
      dep_systemd,
      libpdns_lua_records,
    ],
  )
)

libpdns_auth_ws = declare_dependency(
  link_with: static_library(
    'pdns-auth-ws',
    'ws-auth.cc',
    'ws-auth.hh',
    cpp_args: '-Wno-overloaded-virtual',
    include_directories: toplevel_includes,
    dependencies: [dep_yahttp, dep_json11],
  )
)

libpdns_auth_lua = dependency('', required: false)
if dep_lua.found()
  libpdns_auth_lua = static_library(
    'libpdns-auth-lua',
    'lua-auth4.cc',
    'lua-auth4.hh',
    include_directories: toplevel_includes,
    dependencies: libpdns_lua,
  )

  libpdns_auth_lua = declare_dependency(
    link_with: libpdns_auth_lua,
  )
endif

libpdns_auth = static_library(
  'pdns-auth',
  'auth-caches.cc',
  'auth-caches.hh',
  'auth-carbon.cc',
  'auth-catalogzone.cc',
  'auth-catalogzone.hh',
  'auth-packetcache.cc',
  'auth-packetcache.hh',
  'auth-querycache.cc',
  'auth-querycache.hh',
  'auth-zonecache.cc',
  'auth-zonecache.hh',
  'responsestats-auth.cc',
  'secpoll-auth.cc',
  'secpoll-auth.hh',
  include_directories: toplevel_includes,
  dependencies: [
    libpdns_auth_lua,
    libpdns_auth_main,
    libpdns_auth_ws,
  ],
)
