sources = [
  'httpconnector.cc',
  'pipeconnector.cc',
  'remotebackend.cc',
  'unixconnector.cc',
  'zmqconnector.cc',
]

extras = [
  'testrunner.sh',
  'unittest_http.rb',
  'unittest_json.rb',
  'unittest_pipe.rb',
  'unittest_zeromq.rb',
  'unittest_post.rb',
  'unittest.rb',
  'Gemfile',
  'Gemfile.lock',
  # 'remotebackend_pipe.test',
  # 'remotebackend_unix.test',
  # 'remotebackend_http.test',
  # 'remotebackend_post.test',
  # 'remotebackend_json.test',
  # 'remotebackend_zeromq.test',
  'remotebackend.hh',
]

module_deps = [deps, dep_zeromq]

lib = static_library(
  module_backend_name,
  sources,
  dependencies: module_deps,
  extra_files: extras,
)

dep_name = 'dep_' + module_backend_name
set_variable(dep_name, dependency('', required: false))
if module_opt == 'static'
  dep = declare_dependency(link_whole: lib)
  set_variable(dep_name, dep)
else
  shared_module(module_backend_name, link_whole: lib, name_suffix: 'so')
endif

if get_option('unit-tests-backends')
  libpdns_test_remotebackend = declare_dependency(
    link_with: static_library(
      'pdns-test-remotebackend',
      sources: [
        'httpconnector.cc',
	'pipeconnector.cc',
	'remotebackend.cc',
	'unixconnector.cc',
	'zmqconnector.cc',
        'test-remotebackend.cc',
      ],
      extra_files: ['remotebackend.hh'],
      dependencies: [
        deps,
        libpdns_dnslabeltext,
        libpdns_pkcs11signers,

        source_deps_cache['arguments.cc'],
        source_deps_cache['auth-packetcache.cc'],
        source_deps_cache['auth-querycache.cc'],
        source_deps_cache['auth-zonecache.cc'],
        source_deps_cache['base32.cc'],
        source_deps_cache['base64.cc'],
        source_deps_cache['dns.cc'],
        source_deps_cache['dnsbackend.cc'],
        source_deps_cache['dnsname.cc'],
        source_deps_cache['dnspacket.cc'],
        source_deps_cache['dnsparser.cc'],
        source_deps_cache['dnsrecords.cc'],
        source_deps_cache['dnssecinfra.cc'],
        source_deps_cache['dnswriter.cc'],
        source_deps_cache['ednscookies.cc'],
        source_deps_cache['ednsoptions.cc'],
        source_deps_cache['ednssubnet.cc'],
        source_deps_cache['gss_context.cc'],
        source_deps_cache['iputils.cc'],
        source_deps_cache['json.cc'],
        source_deps_cache['logger.cc'],
        source_deps_cache['misc.cc'],
        source_deps_cache['nameserver.cc'],
        source_deps_cache['nsecrecords.cc'],
        source_deps_cache['qtype.cc'],
        source_deps_cache['rcpgenerator.cc'],
        source_deps_cache['shuffle.cc'],
        source_deps_cache['sillyrecords.cc'],
        source_deps_cache['statbag.cc'],
        source_deps_cache['svc-records.cc'],
        source_deps_cache['ueberbackend.cc'],
        source_deps_cache['unix_utility.cc'],
      ],
    )
  )

  test_binaries = [
    'test-remotebackend-http',
    'test-remotebackend-json',
    'test-remotebackend-pipe',
    'test-remotebackend-post',
    'test-remotebackend-unix',
    'test-remotebackend-zeromq',
  ]

  env = {
    'BOOST_TEST_LOG_LEVEL': 'message',
    'REMOTEBACKEND_ZEROMQ': get_option('module-remote-zeromq') ? '1' : '0',
  }

  foreach test_binary: test_binaries
    name = 'pdns_' + test_binary.underscorify()

    set_variable(
      name,
      executable(
        'pdns-' + test_binary,
        sources: [test_binary + '.cc'],
        extra_files: ['test-remotebackend-keys.hh'],
        dependencies: [module_deps, libpdns_test_remotebackend, dep_boost_test],
      )
    )

    test('PDNS Auth ' + test_binary, get_variable(name), verbose: true, env: env)
  endforeach
endif
