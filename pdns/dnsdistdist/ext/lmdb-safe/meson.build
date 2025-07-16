lib_lmdb_safe = static_library(
  'lmdb-safe',
  'lmdb-safe.cc',
  extra_files: [
    'lmdb-safe.hh',
  ],
  dependencies: [
    dep_pdns,
    dep_lmdb,
  ],
)

dep_lmdb_safe = declare_dependency(
  link_with: lib_lmdb_safe,
  include_directories: include_directories('.'),
)
