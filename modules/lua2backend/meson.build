sources = [
  'lua2api2.cc',
  'lua2backend.cc',
]

extras = [
  'lua2backend.hh',
  'lua2api2.hh',
]

deps = [dep_pdns, dep_libcrypto, dep_lua]

lib = static_library(
  module_backend_name,
  sources,
  dependencies: deps,
  extra_files: extras,
)

dep_name = 'dep_' + module_backend_name
set_variable(dep_name, dependency('', required: false))
if module_opt == 'static'
  dep = declare_dependency(link_with: lib)
  set_variable(dep_name, dep)
else
  shared_module(module_backend_name, link_with: lib)
endif
