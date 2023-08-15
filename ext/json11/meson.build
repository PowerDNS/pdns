module_sources = [
  'json11.cpp',
  'json11.hpp',
]

lib_json11 = static_library(
  'json11',
  module_sources,
)

dep_json11 = declare_dependency(
  link_with: lib_json11,
  include_directories: include_directories('.'),
)
