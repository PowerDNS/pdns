sources = [
  'godbcbackend.cc',
  'sodbc.cc',
]

extras = [
  'godbcbackend.hh',
  'sodbc.hh',

  'schema.mssql.sql',
  '4.0.0_to_4.2.0_schema.mssql.sql',
  '4.2.0_to_4.3.0_schema.mssql.sql',
  '4.3.0_to_4.7.0_schema.mssql.sql',
]

deps = [dep_pdns, dep_libcrypto, dep_odbc]

set_variable('dep_' + module_backend_name, dependency('', required: false))
if module_opt
  lib = static_library(module_backend_name, sources, dependencies: deps, extra_files: extras)
  set_variable('dep_' + module_backend_name, lib)
endif

if module_opt_dyn
  shared_module(module_backend_name, sources, dependencies: deps, extra_files: extras)
endif
