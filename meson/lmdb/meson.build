dep_lmdb = dependency('lmdb', required: true)
conf.set('HAVE_LMDB', dep_lmdb.found(), description: 'Whether we have LMDB')
summary('LMDB', dep_lmdb.found(), bool_yn: true, section: 'LMDB')
if dep_lmdb.found()
  summary('Version', dep_lmdb.version(), bool_yn: true, section: 'LMDB')
endif
