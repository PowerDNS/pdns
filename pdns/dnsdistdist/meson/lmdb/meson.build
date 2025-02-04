opt_lmdb = get_option('lmdb')
dep_lmdb = dependency('lmdb', required: opt_lmdb)

conf.set('HAVE_LMDB', dep_lmdb.found(), description: 'Whether we have LMDB')
summary('LMDB', dep_lmdb.found(), bool_yn: true, section: 'Key-Value')
if dep_lmdb.found()
  summary('LMDB version', dep_lmdb.version(), bool_yn: true, section: 'Key-Value')
endif
