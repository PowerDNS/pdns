sources = [
  'bindbackend2.cc',
  'binddnssec.cc',
]

headers = [
  'bindbackend2.hh',
]

# TODO These should be packaged up some other way (and avoid product_source_dir)
docs = [
  product_source_dir / 'pdns' / 'bind-dnssec.4.2.0_to_4.3.0_schema.sqlite3.sql',
  product_source_dir / 'pdns' / 'bind-dnssec.schema.sqlite3.sql',
]

if get_variable(module_name + '_module')
  lib = static_library(
    module_backend_name,
    sources,
    dependencies: [dep_pdns, dep_libcrypto],
    extra_files: [headers, docs],
  )

  set_variable('dep_static_' + module_name, lib)
endif

if get_variable(module_name + '_dyn_module')
  lib = shared_module(
    module_backend_name,
    sources,
    dependencies: [dep_pdns, dep_libcrypto],
    extra_files: [headers, docs],
  )

  set_variable('dep_dyn_' + module_name, lib)
endif
