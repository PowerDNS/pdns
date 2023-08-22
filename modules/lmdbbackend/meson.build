sources = [
  'lmdbbackend.cc',
]

extras = [
  'lmdbbackend.hh',
]

deps = [dep_pdns, dep_lmdb_safe, dep_boost_serialization]

lib = static_library(
  module_backend_name,
  sources,
  dependencies: deps,
  extra_files: extras,
)

dep_name = 'dep_' + module_backend_name
set_variable(dep_name, dependency('', required: false))
if module_opt == 'static'
  dep = declare_dependency(link_whole: lib)
  set_variable(dep_name, dep)
else
  shared_module(module_backend_name, link_whole: lib)
endif
