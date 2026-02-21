module_sources = files(
  'godbcbackend.cc',
  'sodbc.cc',
)

module_extras = files(
  'godbcbackend.hh',
  'sodbc.hh',
)

module_resources = files(
  'schema.mssql.sql',
  '4.0.0_to_4.2.0_schema.mssql.sql',
  '4.2.0_to_4.3.0_schema.mssql.sql',
  '4.3.0_to_4.7.0_schema.mssql.sql',
)

module_deps = [deps, dep_odbc, libpdns_sqlbackend]
