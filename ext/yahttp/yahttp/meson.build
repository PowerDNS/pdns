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

dep_yahttp = declare_dependency(
  compile_args: '-Wno-overloaded-virtual',
  sources: module_sources,
  include_directories: include_directories('..'),
)
