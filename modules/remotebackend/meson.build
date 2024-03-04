sources = files(
  'httpconnector.cc',
  'pipeconnector.cc',
  'remotebackend.cc',
  'unixconnector.cc',
  'zmqconnector.cc',
)

extras = files(
  'remotebackend.hh',
)

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
  module_remotebackend_lib = declare_dependency(link_whole: lib)
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
    'example.rb',
    'Gemfile',
    'Gemfile.lock',
    'unittest_http.rb',
    'unittest_json.rb',
    'unittest_pipe.rb',
    'unittest_post.rb',
    'unittest.rb',
    'unittest_zeromq.rb',
  )
endif
