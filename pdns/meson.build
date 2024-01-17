fs = import('fs')

libpdns_cdb_sources = files('cdb.cc', 'cdb.hh')

common_sources = []

libpdns_bindlexer_sources = 'bindlexer.c'
if not fs.is_file(libpdns_bindlexer_sources)
  flex = find_program('flex', required: true)

  summary('Flex', flex.found(), bool_yn: true, section: 'BIND Parser')
  summary('Flex Path', flex.full_path(), section: 'BIND Parser')
  summary('Flex Version', flex.version(), section: 'BIND Parser')

  flex_generator = generator(
    flex,
    output: '@BASENAME@.c',
    arguments: ['--case-insensitive', '--outfile=@OUTPUT@', '@INPUT@'],
  )

  libpdns_bindlexer_sources = flex_generator.process('bindlexer.l')
endif

libpdns_bindparser_sources = 'bindparser.cc'
if not fs.is_file(libpdns_bindparser_sources) and not fs.is_file('bindparser.hh')
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

  libpdns_bindparser_sources = bison_generator.process('bindparser.yy')
endif

libpdns_dnslabeltext_sources = 'dnslabeltext.cc'
if not fs.is_file(libpdns_dnslabeltext_sources)
  ragel = find_program('ragel', required: true)
  ragel_generator = generator(
    ragel,
    output: '@BASENAME@.cc',
    arguments: ['@INPUT@', '-o', '@OUTPUT@'],
  )

  summary('Ragel', ragel.found(), bool_yn: ragel.found(), section: 'DNS Labels')
  summary('Ragel Path', ragel.full_path(), section: 'DNS Labels')
  summary('Ragel Version', ragel.version(), section: 'DNS Labels')

  libpdns_dnslabeltext_sources = ragel_generator.process('dnslabeltext.rl')
endif
common_sources += libpdns_dnslabeltext_sources

libpdns_apidocfiles_headers = 'apidocfiles.h'
if not fs.is_file(libpdns_apidocfiles_headers)
  py = import('python')
  python = py.find_installation('python3', modules: 'yaml', required: true)

  summary('Python', python.found(), bool_yn: true, section: 'Swagger API')
  summary('Path', python.full_path(), section: 'Swagger API')
  summary('Version', python.version(), section: 'Swagger API')

  libpdns_apidocfiles_headers = custom_target(
    'pdns-apidocfiles-h',
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
common_sources += libpdns_apidocfiles_headers

libpdns_bind_dnssec_schema_headers = 'bind-dnssec.schema.sqlite3.sql.h'
if not fs.is_file(libpdns_bind_dnssec_schema_headers)
  py = import('python')
  python = py.find_installation('python3', required: true)

  summary('Python', python.found(), bool_yn: true, section: 'BIND DNSSEC Schema')
  summary('Path', python.full_path(), section: 'BIND DNSSEC Schema')
  summary('Version', python.version(), section: 'BIND DNSSEC Schema')

  libpdns_bind_dnssec_schema_headers = custom_target(
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
common_sources += libpdns_bind_dnssec_schema_headers

conditional_sources = {
  'mplexer-sunos-devpoll': {
    'sources': ['devpollmplexer.cc', 'portsmplexer.cc'],
    'condition': have_sunos,
  },
  'mplexer-linux-epoll': {
    'sources': ['epollmplexer.cc'],
    'condition': have_linux,
  },
  'mplexer-bsd-kqueue': {
    'sources': ['kqueuemplexer.cc'],
    'condition': have_openbsd or have_freebsd,
  },
  'ssqlite3': {
    'sources': ['ssqlite3.cc', 'ssqlite3.hh'],
    'condition': dep_sqlite3.found(),
  },
  'minicurl': {
    'sources': ['minicurl.cc', 'minicurl.hh'],
    'condition': dep_lua_records.found() or dep_libcurl.found(),
  },
  'lua-record': {
    'sources': ['lua-record.cc'],
    'condition': dep_lua_records.found(),
  },
  'signers-sodium': {
    'sources': ['sodiumsigners.cc'],
    'condition': dep_libsodium.found(),
  },
  'signers-decaf': {
    'sources': ['decafsigners.cc'],
    'condition': dep_libdecaf.found(),
  },
  'signers-pkcs11': {
    'sources': ['pkcs11signers.cc', 'pkcs11signers.hh'],
    'condition': dep_pkcs11.found(),
  },
  'standalone-fuzz-target-runner': {
    'sources': ['standalone_fuzz_target_runner.cc'],
    'condition': get_option('fuzz-targets'),
  },
}

foreach name, info: conditional_sources
  if info['condition']
    common_sources += files(info['sources'])
  endif
endforeach

common_sources += files(
  'arguments.cc',
  'arguments.hh',
  'auth-caches.cc',
  'auth-caches.hh',
  'auth-carbon.cc',
  'auth-catalogzone.cc',
  'auth-catalogzone.hh',
  'auth-main.hh',
  'auth-packetcache.cc',
  'auth-packetcache.hh',
  'auth-primarycommunicator.cc',
  'auth-querycache.cc',
  'auth-querycache.hh',
  'auth-secondarycommunicator.cc',
  'auth-zonecache.cc',
  'auth-zonecache.hh',
  'axfr-retriever.cc',
  'axfr-retriever.hh',
  'backends' / 'gsql' / 'gsqlbackend.cc', # TODO Move to a separate module.
  'backends' / 'gsql' / 'gsqlbackend.hh', # TODO Move to a separate module.
  'backends' / 'gsql' / 'ssql.hh',        # TODO Move to a separate module.
  'base32.cc',
  'base32.hh',
  'base64.cc',
  'base64.hh',
  'bindparserclasses.hh',
  'burtle.hh',
  'cachecleaner.hh',
  'circular_buffer.hh',
  'comment.hh',
  'communicator.cc',
  'communicator.hh',
  'coverage.cc',
  'coverage.hh',
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
  'dynmessenger.cc',
  'dynmessenger.hh',
  'ednscookies.cc',
  'ednscookies.hh',
  'ednsoptions.cc',
  'ednsoptions.hh',
  'ednssubnet.cc',
  'ednssubnet.hh',
  'gettime.cc',
  'gettime.hh',
  'gss_context.cc',
  'gss_context.hh',
  'histogram.hh',
  'ipcipher.cc',
  'ipcipher.hh',
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
  'lua-auth4.cc',
  'lua-auth4.hh',
  'lua-base4.cc',
  'lua-base4.hh',
  'misc.cc',
  'misc.hh',
  'nameserver.cc',
  'nameserver.hh',
  'namespaces.hh',
  'noinitvector.hh',
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
  'responsestats-auth.cc',
  'responsestats.cc',
  'responsestats.hh',
  'rfc2136handler.cc',
  'secpoll-auth.cc',
  'secpoll-auth.hh',
  'secpoll.cc',
  'secpoll.hh',
  'serialtweaker.cc',
  'sha.hh',
  'shuffle.cc',
  'shuffle.hh',
  'signingpipe.cc',
  'signingpipe.hh',
  'sillyrecords.cc',
  'sstuff.hh',
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
  'tsigutils.cc',
  'tsigutils.hh',
  'tsigverifier.cc',
  'tsigverifier.hh',
  'ueberbackend.cc',
  'ueberbackend.hh',
  'unix_semaphore.cc',
  'unix_utility.cc',
  'utility.hh',
  'uuid-utils.cc',
  'uuid-utils.hh',
  'validate.hh',
  'version.cc',
  'version.hh',
  'webserver.cc',
  'webserver.hh',
  'ws-api.cc',
  'ws-api.hh',
  'ws-auth.cc',
  'ws-auth.hh',
  'zonemd.cc',
  'zonemd.hh',
  'zoneparser-tng.cc',
  'zoneparser-tng.hh',
)

tools = {
  'pdns-auth'         : { 'main': 'auth-main.cc' },
  'pdns-auth-util'    : { 'main': 'pdnsutil.cc'  },
  'pdns-auth-control' : { 'main': 'dynloader.cc' },
  'pdns-zone2sql'     : { 'main': 'zone2sql.cc'  },
  'pdns-zone2json'    : { 'main': 'zone2json.cc' },
}

if get_option('module-ldap') != 'disabled'
  tools += { 'pdns-zone2ldap' : { 'main': 'zone2ldap.cc' } }
endif

if get_option('tools')
  tools += {
    'pdns-auth-notify' : { 'main': 'notify.cc' },

    'sdig'             : {},
    'calidns'          : {},
    'dnsdemog'         : {},
    'dnsgram'          : {},
    'dnspcap2calidns'  : {},
    'dnspcap2protobuf' : {},
    'dnsreplay'        : {},
    'dnsscan'          : {},
    'dnsscope'         : {},
    'dnswasher'        : {},
    'nproxy'           : {},
    'nsec3dig'         : {},
    'dumresp'          : {},
    'kvresp'           : {},
    'stubquery'        : {},
    'saxfr'            : {},
    'ixplore'          : {},
    # 'comfun'         : {}, # Broken
  }

  common_sources += files(
    'anadns.hh',
    'dnspcap.cc',
    'dnspcap.hh',
    'dolog.hh',
    'ednsextendederror.cc',
    'ednsextendederror.hh',
    'histog.hh',
    'ixfrutils.cc',
    'ixfrutils.hh',
    'libssl.cc',
    'libssl.hh',
    'mplexer.hh',
    'pollmplexer.cc',
    'protozero.cc',
    'protozero.hh',
    'statnode.cc',
    'statnode.hh',
    'tcpiohandler.cc',
    'tcpiohandler.hh',
  )

  if have_boost_1_48_0
    tools += {
      'dnstcpbench': {},
      'dnsbulktest': {},
    }
  endif
endif

if get_option('tools-ixfrdist')
  tools += { 'ixfrdist': {} }

  common_sources += files(
    'ixfrdist-stats.cc',
    'ixfrdist-stats.hh',
    'ixfrdist-web.cc',
    'ixfrdist-web.hh',
    'ixfrutils.cc',
    'ixfrutils.hh',
    'mplexer.hh',
    'pollmplexer.cc',
  )
endif

if get_option('unit-tests')
  tools += {
    'pdns-auth-testrunner': { 'main': 'testrunner.cc' },
    'tsig-tests'          : { 'main': 'tsig-tests.cc' },
    'speedtest'           : {},
  }

  common_sources += files(
    'channel.cc',
    'channel.hh',
    'pollmplexer.cc',
    'test-arguments_cc.cc',
    'test-auth-zonecache_cc.cc',
    'test-base32_cc.cc',
    'test-base64_cc.cc',
    'test-bindparser_cc.cc',
    'test-channel.cc',
    'test-common.hh',
    'test-communicator_hh.cc',
    'test-credentials_cc.cc',
    'test-digests_hh.cc',
    'test-distributor_hh.cc',
    'test-dns_random_hh.cc',
    'test-dnsname_cc.cc',
    'test-dnsparser_cc.cc',
    'test-dnsparser_hh.cc',
    'test-dnsrecordcontent.cc',
    'test-dnsrecords_cc.cc',
    'test-dnswriter_cc.cc',
    'test-ednscookie_cc.cc',
    'test-ipcrypt_cc.cc',
    'test-iputils_hh.cc',
    'test-ixfr_cc.cc',
    'test-lock_hh.cc',
    'test-lua_auth4_cc.cc',
    'test-luawrapper.cc',
    'test-misc_hh.cc',
    'test-mplexer.cc',
    'test-nameserver_cc.cc',
    'test-packetcache_cc.cc',
    'test-packetcache_hh.cc',
    'test-proxy_protocol_cc.cc',
    'test-rcpgenerator_cc.cc',
    'test-sha_hh.cc',
    'test-signers.cc',
    'test-statbag_cc.cc',
    'test-svc_records_cc.cc',
    'test-trusted-notification-proxy_cc.cc',
    'test-tsig.cc',
    'test-ueberbackend_cc.cc',
    'test-webserver_cc.cc',
    'test-zonemd_cc.cc',
    'test-zoneparser_tng_cc.cc',
    'zoneparser-tng.hh',
  )
endif

if get_option('fuzz-targets')
  tools += {
    'fuzz-target-moadnsparser'                        : { 'main': 'fuzz_moadnsparser.cc'                        },
    'fuzz-target-packetcache'                         : { 'main': 'fuzz_packetcache.cc'                         },
    'fuzz-target-proxyprotocol'                       : { 'main': 'fuzz_proxyprotocol.cc'                       },
    'fuzz-target-dnslabeltext-parseRFC1035CharString' : { 'main': 'fuzz_dnslabeltext_parseRFC1035CharString.cc' },
    'fuzz-target-yahttp'                              : { 'main': 'fuzz_yahttp.cc'                              },
    'fuzz-target-zoneparsertng'                       : { 'main': 'fuzz_zoneparsertng.cc'                       },
  }
endif

foreach tool, info: tools
  tool_name = tool.underscorify()

  if 'main' in info
    main = info['main']
  else
    main = tool_name + '.cc'
  endif

  set_variable(tool_name + '_sources', files(main))
endforeach
