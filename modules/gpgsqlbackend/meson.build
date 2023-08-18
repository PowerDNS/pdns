sources = [
  'gpgsqlbackend.cc',
  'spgsql.cc',
]

extras = [
  'gpgsqlbackend.hh',
  'spgsql.hh',

  'schema.pgsql.sql',
  'nodnssec-3.x_to_3.4.0_schema.pgsql.sql',
  'dnssec-3.x_to_3.4.0_schema.pgsql.sql',
  '3.4.0_to_4.1.0_schema.pgsql.sql',
  '4.1.0_to_4.2.0_schema.pgsql.sql',
  '4.2.0_to_4.3.0_schema.pgsql.sql',
  '4.3.0_to_4.7.0_schema.pgsql.sql',
]

deps = [dep_pdns, dep_libcrypto, dep_pgsql]

set_variable('dep_' + module_backend_name, dependency('', required: false))
if module_opt
  lib = static_library(module_backend_name, sources, dependencies: deps, extra_files: extras)
  set_variable('dep_' + module_backend_name, lib)
endif

if module_opt_dyn
  shared_module(module_backend_name, sources, dependencies: deps, extra_files: extras)
endif
