module_sources = files(
  'httpconnector.cc',
  'pipeconnector.cc',
  'remotebackend.cc',
  'unixconnector.cc',
  'zmqconnector.cc',
)

module_extras = files(
  'remotebackend.hh',
)

module_deps = [deps, dep_zeromq]

if get_option('unit-tests-backends')
  module_remotebackend_testrunner = files('testrunner.sh')[0]

  module_remotebackend_test_sources_common = files(
    'test-remotebackend.cc',
    'test-remotebackend-keys.hh',
  )

  module_remotebackend_test_sources_binaries = {
    'remotebackend_http.test':   files('test-remotebackend-http.cc'),
    'remotebackend_json.test':   files('test-remotebackend-json.cc'),
    'remotebackend_pipe.test':   files('test-remotebackend-pipe.cc'),
    'remotebackend_post.test':   files('test-remotebackend-post.cc'),
    'remotebackend_unix.test':   files('test-remotebackend-unix.cc'),
    'remotebackend_zeromq.test': files('test-remotebackend-zeromq.cc'),
  }

  module_remotebackend_test_sources_extra = files(
    'requirements.txt',
    'pdns_unittest.py',
    'unittest_http.py',
    'unittest_json.py',
    'unittest_pipe.py',
    'unittest_post.py',
    'unittest_zeromq.py',
  )
endif
