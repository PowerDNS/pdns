module_sources = files(
  'bindbackend2.cc',
  'binddnssec.cc',
)

module_extras = files(
  'bindbackend2.hh',

  # TODO These should be packaged up some other way (and avoid product_source_dir)
  product_source_dir / 'pdns' / 'bind-dnssec.4.2.0_to_4.3.0_schema.sqlite3.sql',
  product_source_dir / 'pdns' / 'bind-dnssec.schema.sqlite3.sql',
)

module_deps = [deps]
