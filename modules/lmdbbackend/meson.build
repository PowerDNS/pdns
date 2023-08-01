sources = [
  # TODO Put this in a libpdns-lmdb library
  '../../ext/lmdb-safe/lmdb-safe.cc',
  '../../ext/lmdb-safe/lmdb-typed.cc',
  'lmdbbackend.cc',
]

if lmdb_module
  static_library('lmdbbackend', sources)
endif

if lmdb_dyn_module
endif
