sources = [
  'gmysqlbackend.cc',
  'smysql.cc',
]

extras = [
  'gmysqlbackend.hh',
  'smysql.hh',

  'dnssec-3.x_to_3.4.0_schema.mysql.sql',
  'enable-foreign-keys.mysql.sql',
  'nodnssec-3.x_to_3.4.0_schema.mysql.sql',
  '3.4.0_to_4.1.0_schema.mysql.sql',
  '4.1.0_to_4.2.0_schema.mysql.sql',
  '4.2.0_to_4.3.0_schema.mysql.sql',
  '4.3.0_to_4.7.0_schema.mysql.sql',
  'schema.mysql.sql',
]

module_deps = [deps, dep_mysql]

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
