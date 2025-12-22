module_sources = files(
  'gpgsqlbackend.cc',
  'spgsql.cc',
)

module_extras = files(
  'gpgsqlbackend.hh',
  'spgsql.hh',
)

module_resources = files(
  'schema.pgsql.sql',
  'nodnssec-3.x_to_3.4.0_schema.pgsql.sql',
  'dnssec-3.x_to_3.4.0_schema.pgsql.sql',
  '3.4.0_to_4.1.0_schema.pgsql.sql',
  '4.1.0_to_4.2.0_schema.pgsql.sql',
  '4.2.0_to_4.3.0_schema.pgsql.sql',
  '4.3.0_to_4.7.0_schema.pgsql.sql',
)

module_deps = [deps, dep_pgsql]
