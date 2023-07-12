# CDB
# Outputs: deps_cdb

deps_cdb = dependency('libcdb', required: false)

if not deps_cdb.found()
  if cxx.has_header('cdb.h', required: true)
    if cxx.has_function('cdb_find', args: ['-lcdb'])
      deps_cdb = declare_dependency(link_args: ['-lcdb'])
    endif
  endif
endif

conf.set10('HAVE_CDB', deps_cdb.found(), description: 'Whether we have CDB')
conf.set10('CDB', deps_cdb.found(), description: 'Whether we have CDB')
summary('CDB', deps_cdb.found(), bool_yn: true, section: 'Configuration')
