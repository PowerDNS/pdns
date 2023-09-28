fs = import('fs')

libpdns_bindlexer_cc = 'bindlexer.c'
if not fs.is_file(libpdns_bindlexer_cc)
  flex = find_program('flex', required: true)

  summary('Flex', flex.found(), bool_yn: true, section: 'BIND Parser')
  summary('Flex Path', flex.full_path(), section: 'BIND Parser')
  summary('Flex Version', flex.version(), section: 'BIND Parser')

  flex_generator = generator(
    flex,
    output: '@BASENAME@.c',
    arguments: ['--case-insensitive', '--outfile=@OUTPUT@', '@INPUT@'],
  )

  libpdns_bindlexer_cc = flex_generator.process('bindlexer.l')
endif
libpdns_bindlexer_cc = declare_dependency(
  sources: [libpdns_bindlexer_cc],
)

libpdns_bindparser_cc = 'bindparser.cc'
if not fs.is_file(libpdns_bindparser_cc) and not fs.is_file('bindparser.hh')
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

  libpdns_bindparser_cc = bison_generator.process('bindparser.yy')
endif
libpdns_bindparser_cc = declare_dependency(
  sources: [libpdns_bindparser_cc],
)

libpdns_bind_parser = declare_dependency(
  link_whole: static_library(
    'pdns-bind-parser',
    'zoneparser-tng.cc',
    extra_files: [
      'zoneparser-tng.hh',
    ],
    cpp_args: '-Wno-redundant-decls',
    dependencies: [
      deps,
      libpdns_bindlexer_cc,
      libpdns_bindparser_cc,
    ],
  )
)

libpdns_lua = dependency('', required: false)
if dep_lua.found()
  libpdns_lua = declare_dependency(
    link_whole: static_library(
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
    link_whole: static_library(
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
  link_whole: static_library(
    'pdns-gss',
    'gss_context.cc',
    extra_files: [
      'gss_context.hh',
    ],
    dependencies: deps,
  )
)

libpdns_sodium = dependency('', required: false)
if dep_libsodium.found()
  libpdns_sodium = declare_dependency(
    link_whole: static_library(
      'pdns-sodium',
      'sodiumsigners.cc',
      dependencies: deps,
    )
  )
endif

libpdns_decaf = dependency('', required: false)
if dep_libdecaf.found()
  libpdns_decaf = declare_dependency(
    link_whole: static_library(
      'pdns-decaf',
      'decafsigners.cc',
      dependencies: deps,
      cpp_args: '-Wno-shadow',
    )
  )
endif

libpdns_pkcs11 = dependency('', required: false)
if dep_pkcs11.found()
  libpdns_pkcs11 = declare_dependency(
    link_whole: static_library(
      'pdns-pkcs11',
      'pkcs11signers.cc',
      extra_files: [
        'pkcs11signers.hh',
      ],
      dependencies: deps,
    )
  )
endif

libpdns_sqlite3 = dependency('', required: false)
if get_variable('dep_sqlite3', dependency('', required: false)).found()
  libpdns_sqlite3 = declare_dependency(
    link_whole: static_library(
      'pdns-sqlite3',
      'ssqlite3.cc',
      extra_files: [
        'ssqlite3.hh',
      ],
      dependencies: deps,
    )
  )
endif

libpdns_ws = declare_dependency(
  link_whole: static_library(
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
  link_whole: static_library(
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

libpdns_dnslabeltext_cc = 'dnslabeltext.cc'
if not fs.is_file(libpdns_dnslabeltext_cc)
  ragel = find_program('ragel', required: true)
  ragel_generator = generator(
    ragel,
    output: '@BASENAME@.cc',
    arguments: ['@INPUT@', '-o', '@OUTPUT@'],
  )

  summary('Ragel', ragel.found(), bool_yn: ragel.found(), section: 'DNS Labels')
  summary('Ragel Path', ragel.full_path(), section: 'DNS Labels')
  summary('Ragel Version', ragel.version(), section: 'DNS Labels')

  libpdns_dnslabeltext_cc = ragel_generator.process('dnslabeltext.rl')
endif

libpdns_base = declare_dependency(
  link_whole: static_library(
    'pdns-base',
    'arguments.cc',
    'axfr-retriever.cc',
    # TODO Move to a separate module
    'backends' / 'gsql' / 'gsqlbackend.cc',
    'base32.cc',
    'base64.cc',
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
    'dynlistener.cc',
    'ednscookies.cc',
    'ednsoptions.cc',
    'ednssubnet.cc',
    'gettime.cc',
    'iputils.cc',
    'ixfr.cc',
    'json.cc',
    'logger.cc',
    'misc.cc',
    'nsecrecords.cc',
    'opensslsigners.cc',
    'proxy-protocol.cc',
    'qtype.cc',
    'query-local-address.cc',
    'rcpgenerator.cc',
    'resolver.cc',
    'responsestats.cc',
    'secpoll.cc',
    'serialtweaker.cc',
    'shuffle.cc',
    'signingpipe.cc',
    'sillyrecords.cc',
    'statbag.cc',
    'stubresolver.cc',
    'svc-records.cc',
    'threadname.cc',
    'trusted-notification-proxy.cc',
    'ueberbackend.cc',
    'unix_semaphore.cc',
    'unix_utility.cc',
    'uuid-utils.cc',
    'version.cc',
    libpdns_dnslabeltext_cc,
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
      'namespaces.hh',
      'noinitvector.hh',
      'opensslsigners.hh',
      'packetcache.hh',
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
      libpdns_gss,
      libpdns_lua,
      libpdns_pkcs11,
      libpdns_tsig,
      libpdns_sodium,
      libpdns_decaf,
      libpdns_sqlite3,
    ],
  )
)

libpdns = declare_dependency(
  link_whole: static_library(
    'pdns',
    'communicator.cc',
    'dynhandler.cc',
    'mastercommunicator.cc',
    'nameserver.cc',
    'packethandler.cc',
    'rfc2136handler.cc',
    'slavecommunicator.cc',
    'tcpreceiver.cc',
    'tkey.cc',
    extra_files: [
      'communicator.hh',
      'dynhandler.hh',
      'nameserver.hh',
      'packethandler.hh',
      'tcpreceiver.hh',
    ],
    dependencies: [
      deps,
      libpdns_base,
      libpdns_ws,
    ],
  )
)

libpdns_auth_apidocfiles_h = 'apidocfiles.h'
if not fs.is_file(libpdns_auth_apidocfiles_h)
  py = import('python')
  python = py.find_installation('python3', modules: 'yaml', required: true)

  summary('Python', python.found(), bool_yn: true, section: 'Swagger API')
  summary('Path', python.full_path(), section: 'Swagger API')
  summary('Version', python.version(), section: 'Swagger API')

  libpdns_auth_apidocfiles_h = custom_target(
    'pdns-auth-apidocfiles-h',
    command: [
      python,
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
libpdns_auth_apidocfiles_h = declare_dependency(
  sources: [libpdns_auth_apidocfiles_h],
)

libpdns_auth_main = declare_dependency(
  link_whole: static_library(
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
  link_whole: static_library(
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
    link_whole: static_library(
      'pdns-auth-lua',
      'lua-auth4.cc',
      extra_files: [
        'lua-auth4.hh',
      ],
      dependencies: deps,
    )
  )
endif

libpdns_auth_sources = [
  'auth-caches.cc',
  'auth-carbon.cc',
  'auth-catalogzone.cc',
  'auth-packetcache.cc',
  'auth-querycache.cc',
  'auth-zonecache.cc',
  'responsestats-auth.cc',
  'secpoll-auth.cc',
]

if get_variable('dep_sqlite3', dependency('', required: false)).found()
  libpdns_auth_sources += 'ssqlite3.cc'
endif

libpdns_auth = declare_dependency(
  link_whole: static_library(
    'pdns-auth',
    libpdns_auth_sources,
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
      libpdns_auth_apidocfiles_h,
      libpdns_auth_lua,
    ],
  )
)

libpdns_bind_dnssec_schema_h = 'bind-dnssec.schema.sqlite3.sql.h'
if not fs.is_file(libpdns_bind_dnssec_schema_h)
  py = import('python')
  python = py.find_installation('python3', required: true)

  summary('Python', python.found(), bool_yn: true, section: 'BIND DNSSEC Schema')
  summary('Path', python.full_path(), section: 'BIND DNSSEC Schema')
  summary('Version', python.version(), section: 'BIND DNSSEC Schema')

  libpdns_bind_dnssec_schema_h = custom_target(
    'pdns-bind-dnssec-schema',
    command: [
      python,
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
libpdns_bind_dnssec_schema_h = declare_dependency(
  sources: [libpdns_bind_dnssec_schema_h],
)

libpdns_ipcipher = dependency('', required: false)
if enable_ipcipher
  libpdns_ipcipher = declare_dependency(
    link_whole: static_library(
      'pdns-ipcipher',
      'ipcipher.cc',
      dependencies: deps,
    )
  )
endif

libpdns_util = declare_dependency(
  link_whole: static_library(
    'pdns-util',
    'pdnsutil.cc',
    'zonemd.cc',
    extra_files: [
      'zonemd.hh',
    ],
    dependencies: [
      deps,
      libpdns_bind_dnssec_schema_h,
      libpdns_ipcipher,
    ],
  )
)
