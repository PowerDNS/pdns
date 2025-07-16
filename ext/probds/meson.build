lib_probds = static_library(
  'probds',
  'murmur3.cc',
  extra_files: [
    'murmur3.h',
  ],
)

dep_probds = declare_dependency(
  link_with: lib_probds,
  include_directories: include_directories('.'),
)
