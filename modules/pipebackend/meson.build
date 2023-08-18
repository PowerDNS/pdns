sources = [
  'coprocess.cc',
  'pipebackend.cc',
]

extras = [
  'coprocess.hh',
  'pipebackend.hh',

  'backend.pl',
]

deps = [dep_pdns, dep_libcrypto]

set_variable('dep_' + module_backend_name, dependency('', required: false))
if module_opt
  lib = static_library(module_backend_name, sources, dependencies: deps, extra_files: extras)
  set_variable('dep_' + module_backend_name, lib)
endif

if module_opt_dyn
  shared_module(module_backend_name, sources, dependencies: deps, extra_files: extras)
endif
