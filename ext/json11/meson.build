lib_json11 = static_library(
  'json11',
  'json11.cpp',
  extra_files: [
    'json11.hpp',
  ],
)

dep_json11 = declare_dependency(
  link_with: lib_json11,
  include_directories: include_directories('.'),
)
