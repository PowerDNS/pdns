fs = import('fs')

libpdns_cdb = dependency('', required: false)
if dep_cdb.found()
  libpdns_cdb = declare_dependency(
    link_whole: static_library(
      'libpdns-cdb',
      'cdb.cc',
      extra_files: [
        'cdb.hh',
      ],
      dependencies: [
        deps,
      ],
    )
  )
endif

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
libpdns_bindlexer = declare_dependency(
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
libpdns_bindparser = declare_dependency(
  sources: [libpdns_bindparser_cc],
)

libpdns_bind_parser = declare_dependency(
  link_whole: static_library(
    'pdns-bind-parser',
    'zoneparser-tng.cc',
    extra_files: [
      'bindparserclasses.hh',
      'zoneparser-tng.hh',
    ],
    cpp_args: '-Wno-redundant-decls',
    dependencies: [
      deps,
      libpdns_bindlexer,
      libpdns_bindparser,
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

libpdns_minicurl = dependency('', required: false)
if dep_libcurl.found()
  libpdns_minicurl = declare_dependency(
    link_whole: static_library(
      'pdns-minicurl',
      'minicurl.cc',
      extra_files: [
        'minicurl.hh',
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
      extra_files: [],
      dependencies: [
        deps,
        libpdns_minicurl,
      ],
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

libpdns_tsig = dependency('', required: false)
if dep_gss_tsig.found()
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
endif

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
libpdns_dnslabeltext = declare_dependency(
  sources: [libpdns_dnslabeltext_cc],
)

libpdns_common = declare_dependency(
  link_whole: static_library(
    'pdns-common',
    sources: [
      'arguments.cc',
      'base32.cc',
      'base64.cc',
      'dns.cc',
      'dnsname.cc',
      'dnsparser.cc',
      'dnsrecords.cc',
      'dnswriter.cc',
      'ednsoptions.cc',
      'ednssubnet.cc',
      'iputils.cc',
      'json.cc',
      'logger.cc',
      'misc.cc',
      'nsecrecords.cc',
      'proxy-protocol.cc',
      'qtype.cc',
      'rcpgenerator.cc',
      'sillyrecords.cc',
      'statbag.cc',
      'svc-records.cc',
      'unix_utility.cc',
    ],
    extra_files: [
      'arguments.hh',
      'base32.hh',
      'base64.hh',
      'dns.hh',
      'dns_random.hh',
      'dnsname.hh',
      'dnsparser.hh',
      'dnsrecords.hh',
      'dnswriter.hh',
      'ednsoptions.hh',
      'ednssubnet.hh',
      'iputils.hh',
      'json.hh',
      'logger.hh',
      'misc.hh',
      'proxy-protocol.hh',
      'qtype.hh',
      'rcpgenerator.hh',
      'statbag.hh',
      'svc-records.hh',
      'utility.hh',
    ],
    dependencies: [
      deps,
      libpdns_dnslabeltext,
    ],
  )
)

libpdns_dnssecinfra = declare_dependency(
  link_whole: static_library(
    'pdns-dnssecinfra',
    sources: [
      'dnssecinfra.cc',
    ],
    extra_files: [
      'dnssecinfra.hh',
    ],
    dependencies: [
      deps,
      libpdns_common,
    ],
  )
)

libpdns_stubresolver = declare_dependency(
  link_whole: static_library(
    'pdns-stubresolver',
    sources: [
      'stubresolver.cc',
    ],
    extra_files: [
      'stubresolver.hh',
    ],
    dependencies: [
      deps,
      libpdns_common,
    ],
  )
)

libpdns_base = declare_dependency(
  link_whole: static_library(
    'pdns-base',
    sources: [
      'axfr-retriever.cc',
      'backends' / 'gsql' / 'gsqlbackend.cc', # TODO Move to a separate module
      'credentials.cc',
      'dbdnsseckeeper.cc',
      'dnsbackend.cc',
      'dnspacket.cc',
      'dnsproxy.cc',
      'dnssecsigner.cc',
      'dynlistener.cc',
      'ednscookies.cc',
      'gettime.cc',
      'ixfr.cc',
      'opensslsigners.cc',
      'query-local-address.cc',
      'resolver.cc',
      'responsestats.cc',
      'secpoll.cc',
      'serialtweaker.cc',
      'shuffle.cc',
      'signingpipe.cc',
      'threadname.cc',
      'trusted-notification-proxy.cc',
      'ueberbackend.cc',
      'unix_semaphore.cc',
      'uuid-utils.cc',
      'version.cc',
    ],
    extra_files: [
      'axfr-retriever.hh',
      'backends' / 'gsql' / 'gsqlbackend.hh', # TODO Move to a separate module
      'backends' / 'gsql' / 'ssql.hh',        # TODO Move to a separate module
      'burtle.hh',
      'cachecleaner.hh',
      'circular_buffer.hh',
      'comment.hh',
      'credentials.hh',
      'digests.hh',
      'distributor.hh',
      'dnsbackend.hh',
      'dnspacket.hh',
      'dnsproxy.hh',
      'dnsseckeeper.hh',
      'dynhandler.hh',
      'dynlistener.hh',
      'dynmessenger.hh',
      'ednscookies.hh',
      'gettime.hh',
      'histogram.hh',
      'ixfr.hh',
      'lock.hh',
      'logging.hh',
      'namespaces.hh',
      'noinitvector.hh',
      'opensslsigners.hh',
      'packetcache.hh',
      'pdnsexception.hh',
      'query-local-address.hh',
      'resolver.hh',
      'responsestats.hh',
      'secpoll.hh',
      'sha.hh',
      'shuffle.hh',
      'signingpipe.hh',
      'stat_t.hh',
      'threadname.hh',
      'trusted-notification-proxy.hh',
      'ueberbackend.hh',
      'uuid-utils.hh',
      'version.hh',
    ],
    dependencies: [
      deps,
      libpdns_common,
      libpdns_dnssecinfra,
      libpdns_stubresolver,
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

libpdns_auth = declare_dependency(
  link_whole: static_library(
    'pdns-auth',
    'auth-caches.cc',
    'auth-carbon.cc',
    'auth-catalogzone.cc',
    'auth-packetcache.cc',
    'auth-querycache.cc',
    'auth-zonecache.cc',
    'responsestats-auth.cc',
    'secpoll-auth.cc',
    extra_files: [
      'auth-caches.hh',
      'auth-catalogzone.hh',
      'auth-packetcache.hh',
      'auth-querycache.hh',
      'auth-zonecache.hh',
      'secpoll-auth.hh',
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
libpdns_bind_dnssec_schema = declare_dependency(
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

tool_libs = {
  'util': {
    'sources': ['pdnsutil.cc', 'zonemd.cc'],
    'headers': ['zonemd.hh'],
    'deps': [deps, libpdns_base, libpdns_auth, libpdns_bind_dnssec_schema, libpdns_ipcipher],
  },
  'auth-control': {
    'sources': ['dynloader.cc', 'dynmessenger.cc'],
    'headers': ['dynmessenger.hh'],
    'deps': [deps, libpdns_common],
  },
  'zone2sql': {
    'sources': ['zone2sql.cc'],
    'headers': [],
    'deps': [deps, libpdns_common, libpdns_bind_parser],
  },
  'zone2ldap': {
    'sources': ['zone2ldap.cc'],
    'headers': [],
    'deps': [deps, libpdns_common, libpdns_bind_parser, libpdns_bind_dnssec_schema],
  },
  'zone2json': {
    'sources': ['zone2json.cc'],
    'headers': [],
    'deps': [deps, libpdns_common, libpdns_bind_parser, libpdns_bind_dnssec_schema],
  },
  'sdig': {
    'sources': ['ednsextendederror.cc', 'libssl.cc', 'sdig.cc', 'tcpiohandler.cc'],
    'headers': ['dolog.hh', 'ednsextendederror.hh', 'libssl.hh', 'sstuff.hh', 'tcpiohandler.hh'],
    'deps': [deps, libpdns_common, libpdns_minicurl],
  },
  'calidns': {
    'sources': ['calidns.cc'],
    'headers': ['sstuff.hh'],
    'deps': [deps, libpdns_common],
  },
  'dumresp': {
    'sources': ['dumresp.cc'],
    'headers': [],
    'deps': [deps, libpdns_common],
  },
  'kvresp': {
    'sources': ['kvresp.cc'],
    'headers': [],
    'deps': [deps, libpdns_common],
  },
  'stubquery': {
    'sources': ['stubquery.cc'],
    'headers': [],
    'deps': [deps, libpdns_common, libpdns_stubresolver],
  },
  'saxfr': {
    'sources': ['saxfr.cc'],
    'headers': [],
    'deps': [deps, libpdns_common, libpdns_gss, libpdns_pkcs11, libpdns_tsig, libpdns_dnssecinfra],
  },
}

foreach tool_name, tool_info: tool_libs
  set_variable(
    'libpdns_' + tool_name.underscorify(),
    declare_dependency(
      link_whole: static_library(
        'pdns-' + tool_name,
        sources: tool_info['sources'],
        extra_files: tool_info['headers'],
        dependencies: tool_info['deps'],
      )
    )
  )
endforeach
