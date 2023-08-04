module_sources = [
  'lua2api2.cc',
  'lua2backend.cc',

  # Headers
  'lua2backend.hh',
  'lua2api2.hh',
  # config_h,
]

if get_variable(module_name + '_module')
  static_library(module_backend_name, module_sources, include_directories: module_includes, dependencies: [dep_libcrypto, dep_lua])
endif

if get_variable(module_name + '_dyn_module')

endif
