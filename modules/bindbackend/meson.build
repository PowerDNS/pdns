sources = [
  'bindbackend2.cc',
  'binddnssec.cc',
]

extras = [
  'bindbackend2.hh',

  # TODO These should be packaged up some other way (and avoid product_source_dir)
  product_source_dir / 'pdns' / 'bind-dnssec.4.2.0_to_4.3.0_schema.sqlite3.sql',
  product_source_dir / 'pdns' / 'bind-dnssec.schema.sqlite3.sql',
]

module_deps = [deps]

lib = static_library(
  module_backend_name,
  sources,
  dependencies: [
    module_deps,
    libpdns_bindparser,
  ],
  extra_files: extras,
)

dep_name = 'dep_' + module_backend_name
set_variable(dep_name, dependency('', required: false))
if module_opt == 'static'
  dep = declare_dependency(link_whole: lib)
  set_variable(dep_name, dep)
else
  shared_module(module_backend_name, link_whole: lib, name_suffix: 'so')
endif
