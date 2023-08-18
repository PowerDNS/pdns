sources = [
  'bindbackend2.cc',
  'binddnssec.cc',
]

extras = [
  'bindbackend2.hh',

  # TODO These should be packaged up some other way (and avoid product_source_dir)
  product_source_dir / 'pdns' / 'bind-dnssec.4.2.0_to_4.3.0_schema.sqlite3.sql',
  product_source_dir / 'pdns' / 'bind-dnssec.schema.sqlite3.sql',
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
