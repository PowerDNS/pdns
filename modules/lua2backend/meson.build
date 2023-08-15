sources = [
  'lua2api2.cc',
  'lua2backend.cc',
]

headers = [
  'lua2backend.hh',
  'lua2api2.hh',
]

if get_variable(module_name + '_module')
  static_library(
    module_backend_name,
    sources,
    dependencies: [dep_pdns, dep_libcrypto, dep_lua],
    extra_files: [headers],
  )
endif

if get_variable(module_name + '_dyn_module')

endif
