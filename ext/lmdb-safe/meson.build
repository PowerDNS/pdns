lib_lmdb_safe = static_library(
  'lmdb-safe',
  'lmdb-safe.cc',
  'lmdb-typed.cc',
  extra_files: [
    'lmdb-safe.hh',
    'lmdb-typed.hh',
  ],
  dependencies: [dep_pdns, dep_lmdb],
)

dep_lmdb_safe = declare_dependency(
  link_whole: lib_lmdb_safe,
  include_directories: include_directories('.'),
)
