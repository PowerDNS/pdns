sources = [
  'gsqlite3backend.cc',
]

extras = [
  'gsqlite3backend.hh',

  'dnssec-3.x_to_3.4.0_schema.sqlite3.sql',
  'nodnssec-3.x_to_3.4.0_schema.sqlite3.sql',
  '3.4.0_to_4.0.0_schema.sqlite3.sql',
  '4.0.0_to_4.2.0_schema.sqlite3.sql',
  '4.2.0_to_4.3.0_schema.sqlite3.sql',
  '4.3.0_to_4.3.1_schema.sqlite3.sql',
  '4.3.1_to_4.7.0_schema.sqlite3.sql',
  'schema.sqlite3.sql',
]

module_deps = [deps, dep_sqlite3]
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
