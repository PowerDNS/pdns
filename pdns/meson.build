libpdns_bind_parser = declare_dependency(
  link_with: static_library(
    'pdns-bind-parser',
    'zoneparser-tng.cc',
    flex_generator.process('bindlexer.l'),
    bison_generator.process('bindparser.yy'),
    extra_files: [
      'zoneparser-tng.hh',
    ],
    cpp_args: '-Wno-redundant-decls',
    dependencies: deps,
  )
)

libpdns_lua = dependency('', required: false)
if dep_lua.found()
  libpdns_lua = declare_dependency(
    link_with: static_library(
      'pdns-lua',
      'lua-base4.cc',
      extra_files: [
        'lua-base4.hh',
      ],
      dependencies: deps,
    )
  )
endif

libpdns_lua_records = dependency('', required: false)
if dep_lua_records.found()
  libpdns_lua_records = declare_dependency(
    link_with: static_library(
      'pdns-lua-records',
      'lua-record.cc',
      'minicurl.cc',
      extra_files: [
        'minicurl.hh',
      ],
      dependencies: deps,
    )
  )
endif

libpdns_gss = dependency('', required: false)
libpdns_gss = declare_dependency(
  link_with: static_library(
    'pdns-gss',
    'gss_context.cc',
    extra_files: [
      'gss_context.hh',
    ],
    dependencies: deps,
  )
)

libpdns_pkcs11 = dependency('', required: false)
if dep_pkcs11.found()
  libpdns_pkcs11 = declare_dependency(
    link_with: static_library(
      'pdns-pkcs11',
      'pkcs11signers.cc',
      extra_files: [
        'pkcs11signers.hh',
      ],
      dependencies: deps,
    )
  )
endif

libpdns_ws = declare_dependency(
  link_with: static_library(
    'pdns-ws',
    'webserver.cc',
    'ws-api.cc',
    extra_files: [
      'webserver.hh',
      'ws-api.hh',
    ],
    cpp_args: '-Wno-overloaded-virtual',
    dependencies: deps,
  )
)

libpdns_tsig = declare_dependency(
  link_with: static_library(
    'pdns-tsig',
    'tsigutils.cc',
    'tsigverifier.cc',
    extra_files: [
      'tsigutils.hh',
      'tsigverifier.hh',
    ],
    cpp_args: '-Wno-redundant-decls',
    dependencies: deps,
  )
)

libpdns = declare_dependency(
  link_with: static_library(
    'pdns',
    'arguments.cc',
    'axfr-retriever.cc',
    'backends/gsql/gsqlbackend.cc',
    'base32.cc',
    'base64.cc',
    'communicator.cc',
    'credentials.cc',
    'dbdnsseckeeper.cc',
    'dns.cc',
    'dnsbackend.cc',
    'dnsname.cc',
    'dnspacket.cc',
    'dnsparser.cc',
    'dnsproxy.cc',
    'dnsrecords.cc',
    'dnssecinfra.cc',
    'dnssecsigner.cc',
    'dnswriter.cc',
    'dynhandler.cc',
    'dynlistener.cc',
    'ednscookies.cc',
    'ednsoptions.cc',
    'ednssubnet.cc',
    'gettime.cc',
    'iputils.cc',
    'ixfr.cc',
    'json.cc',
    'logger.cc',
    'mastercommunicator.cc',
    'misc.cc',
    'nameserver.cc',
    'nsecrecords.cc',
    'opensslsigners.cc',
    'packethandler.cc',
    'proxy-protocol.cc',
    'qtype.cc',
    'query-local-address.cc',
    'rcpgenerator.cc',
    'resolver.cc',
    'responsestats.cc',
    'rfc2136handler.cc',
    'secpoll.cc',
    'serialtweaker.cc',
    'shuffle.cc',
    'signingpipe.cc',
    'sillyrecords.cc',
    'slavecommunicator.cc',
    'statbag.cc',
    'stubresolver.cc',
    'svc-records.cc',
    'tcpreceiver.cc',
    'threadname.cc',
    'tkey.cc',
    'trusted-notification-proxy.cc',
    'ueberbackend.cc',
    'unix_semaphore.cc',
    'unix_utility.cc',
    'uuid-utils.cc',
    'version.cc',
    'zoneparser-tng.cc',
    fs.is_file('dnslabeltext.cc') ? 'dnslabeltext.cc' : ragel_generator.process('dnslabeltext.rl'),
    extra_files: [
      'arguments.hh',
      'axfr-retriever.hh',
      'backends/gsql/gsqlbackend.hh',
      'backends/gsql/ssql.hh',
      'base32.hh',
      'base64.hh',
      'burtle.hh',
      'cachecleaner.hh',
      'circular_buffer.hh',
      'comment.hh',
      'communicator.hh',
      'credentials.hh',
      'digests.hh',
      'distributor.hh',
      'dns.hh',
      'dns_random.hh',
      'dnsbackend.hh',
      'dnsname.hh',
      'dnspacket.hh',
      'dnsparser.hh',
      'dnsproxy.hh',
      'dnsrecords.hh',
      'dnssecinfra.hh',
      'dnsseckeeper.hh',
      'dnswriter.hh',
      'dynhandler.hh',
      'dynlistener.hh',
      'dynmessenger.hh',
      'ednscookies.hh',
      'ednsoptions.hh',
      'ednssubnet.hh',
      'gettime.hh',
      'histogram.hh',
      'iputils.hh',
      'ixfr.hh',
      'json.hh',
      'lock.hh',
      'logger.hh',
      'logging.hh',
      'misc.hh',
      'nameserver.hh',
      'namespaces.hh',
      'noinitvector.hh',
      'opensslsigners.hh',
      'packetcache.hh',
      'packethandler.hh',
      'pdnsexception.hh',
      'proxy-protocol.hh',
      'qtype.hh',
      'query-local-address.hh',
      'rcpgenerator.hh',
      'resolver.hh',
      'responsestats.hh',
      'secpoll.hh',
      'sha.hh',
      'shuffle.hh',
      'signingpipe.hh',
      'stat_t.hh',
      'statbag.hh',
      'stubresolver.hh',
      'svc-records.hh',
      'tcpreceiver.hh',
      'threadname.hh',
      'trusted-notification-proxy.hh',
      'ueberbackend.hh',
      'utility.hh',
      'uuid-utils.hh',
      'version.hh',
    ],
    dependencies: [
      deps,
      libpdns_bind_parser,
      libpdns_lua,
      libpdns_lua_records,
      libpdns_gss,
      libpdns_tsig,
      libpdns_pkcs11,
      libpdns_ws,
    ],
  )
)

libpdns_auth_api_swagger = 'apidocfiles.h'
if not fs.is_file('apidocfiles.h')
  libpdns_auth_api_swagger = custom_target(
    'libpdns-auth-api-swagger',
    command: [
      python_prog,
      '@INPUT0@',
      '@INPUT1@',
    ],
    input: [
      'generate-api-swagger.py',
      product_source_dir / 'docs' / 'http-api' / 'swagger' / 'authoritative-api-swagger.yaml',
    ],
    output: 'apidocfiles.h',
    capture: true,
  )
endif
libpdns_auth_api_swagger = declare_dependency(
  sources: [libpdns_auth_api_swagger],
)

libpdns_auth_main = declare_dependency(
  link_with: static_library(
    'pdns-auth-main',
    'auth-main.cc',
    extra_files: [
      'auth-main.hh',
    ],
    cpp_args: '-Wno-overloaded-virtual',
    dependencies: deps,
  )
)

libpdns_auth_ws = declare_dependency(
  link_with: static_library(
    'pdns-auth-ws',
    'ws-auth.cc',
    extra_files: [
      'ws-auth.hh',
    ],
    cpp_args: '-Wno-overloaded-virtual',
    dependencies: deps,
  )
)

libpdns_auth_lua = dependency('', required: false)
if dep_lua.found()
  libpdns_auth_lua = declare_dependency(
    link_with: static_library(
      'pdns-auth-lua',
      'lua-auth4.cc',
      extra_files: [
        'lua-auth4.hh',
      ],
      dependencies: deps,
    )
  )
endif

libpdns_auth = declare_dependency(
  link_with: static_library(
    'libpdns-auth',
    'auth-caches.cc',
    'auth-carbon.cc',
    'auth-catalogzone.cc',
    'auth-packetcache.cc',
    'auth-querycache.cc',
    'auth-zonecache.cc',
    'responsestats-auth.cc',
    'secpoll-auth.cc',
    'ssqlite3.cc',
    extra_files: [
      'auth-caches.hh',
      'auth-catalogzone.hh',
      'auth-packetcache.hh',
      'auth-querycache.hh',
      'auth-zonecache.hh',
      'secpoll-auth.hh',
      'ssqlite3.hh',
    ],
    dependencies: [
      deps,
      libpdns_auth_api_swagger,
      libpdns_auth_lua,
    ],
  )
)

libpdns_bind_dnssec_schema = 'bind-dnssec.schema.sqlite3.sql.h'
if not fs.is_file('bind-dnssec.schema.sqlite3.sql.h')
  libpdns_bind_dnssec_schema = custom_target(
    'libpdns-bind-dnssec-schema',
    command: [
      python_prog,
      '@INPUT0@',
      '@INPUT1@',
    ],
    input: [
      'generate-bind-dnssec-schema.py',
      'bind-dnssec.schema.sqlite3.sql',
    ],
    output: 'bind-dnssec.schema.sqlite3.sql.h',
    capture: true,
  )
endif
libpdns_bind_dnssec_schema = declare_dependency(
  sources: [libpdns_bind_dnssec_schema],
)

libpdns_ipcipher = dependency('', required: false)
if enable_ipcipher
  libpdns_ipcipher = declare_dependency(
    link_with: static_library(
      'libpdns-ipcipher',
      'ipcipher.cc',
      dependencies: deps,
    )
  )
endif

libpdns_util = declare_dependency(
  link_with: static_library(
    'pdns-util',
    'pdnsutil.cc',
    'zonemd.cc',
    extra_files: [
      'zonemd.hh',
    ],
    dependencies: [
      deps,
      libpdns_bind_dnssec_schema,
      libpdns_ipcipher,
    ],
  )
)
