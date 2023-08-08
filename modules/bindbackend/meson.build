module_sources = [
  'bindbackend2.cc',
  'binddnssec.cc',

  # Headers
  'bindbackend2.hh',
  # config_h,

  # TODO These should be in their own library (and avoid product_source_dir)
  flex_generator.process(product_source_dir / 'pdns' / 'bindlexer.l'),
  bison_generator.process(product_source_dir / 'pdns' / 'bindparser.yy'),
]

# TODO These should be packaged up some other way (and avoid product_source_dir)
module_docs = [
  product_source_dir / 'pdns' / 'bind-dnssec.4.2.0_to_4.3.0_schema.sqlite3.sql',
  product_source_dir / 'pdns' / 'bind-dnssec.schema.sqlite3.sql',
]

if get_variable(module_name + '_module')
  lib = static_library(
    module_backend_name,
    module_sources,
    include_directories: toplevel_includes,
    dependencies: dep_libcrypto,
    extra_files: module_docs
  )

  set_variable('dep_static_' + module_name, lib)
endif

if get_variable(module_name + '_dyn_module')
  lib = shared_library(
    module_backend_name,
    module_sources,
    include_directories: toplevel_includes,
    dependencies: dep_libcrypto,
    extra_files: module_docs
  )

  set_variable('dep_dyn_' + module_name, lib)
endif
