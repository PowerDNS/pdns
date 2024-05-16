module_sources = files(
  'gmysqlbackend.cc',
  'smysql.cc',
)

module_extras = files(
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
)

module_deps = [deps, dep_mysql]
