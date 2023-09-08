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
