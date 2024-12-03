lib_yahttp = static_library(
  'yahttp',
  'reqresp.cpp',
  'router.cpp',
  extra_files: [
    'cookie.hpp',
    'exception.hpp',
    'reqresp.hpp',
    'router.hpp',
    'url.hpp',
    'utility.hpp',
    'yahttp-config.h',
    'yahttp.hpp',
  ],
  cpp_args: '-Wno-overloaded-virtual',
  dependencies: [dep_pdns],
)

dep_yahttp = declare_dependency(
  link_with: lib_yahttp,
  include_directories: include_directories('..'),
)

dep_yahttp_header_only = declare_dependency(
  include_directories: include_directories('..'),
)
