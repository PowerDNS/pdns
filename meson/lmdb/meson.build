# LMDB
# Inputs: conf
# Outputs: deps_lmdb

deps_lmdb = dependency('lmdb', required: true)
conf.set10('HAVE_LMDB', deps_lmdb.found(), description: 'Whether we have LMDB')
conf.set10('LMDB', deps_lmdb.found(), description: 'Whether we have LMDB')
summary('LMDB', deps_lmdb.found(), bool_yn: true, section: 'Configuration')
