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

module_deps = [deps, dep_odbc]

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
  shared_module(module_backend_name, link_whole: lib)
endif
