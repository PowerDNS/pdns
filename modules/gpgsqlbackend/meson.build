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
