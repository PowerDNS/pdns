module_sources = [
  'cookie.hpp',
  'exception.hpp',
  'reqresp.cpp',
  'reqresp.hpp',
  'router.cpp',
  'router.hpp',
  'url.hpp',
  'utility.hpp',
  'yahttp-config.h',
  'yahttp.hpp',
]

lib_yahttp = static_library(
  'yahttp',
  module_sources,
  cpp_args: '-Wno-overloaded-virtual',
  dependencies: [dep_pdns],
)

dep_yahttp = declare_dependency(
  link_with: lib_yahttp,
  include_directories: include_directories('..'),
)
