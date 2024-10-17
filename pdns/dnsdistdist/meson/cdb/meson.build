dep_cdb = dependency('libcdb', required: false)

if not dep_cdb.found()
  if cxx.has_header('cdb.h', required: false)
    if cxx.has_function('cdb_find', args: ['-lcdb'])
      dep_cdb = declare_dependency(link_args: ['-lcdb'])
    endif
  endif
endif

conf.set('HAVE_CDB', dep_cdb.found(), description: 'Whether we have CDB')

summary('CDB', dep_cdb.found(), bool_yn: true, section: 'Key-Value')

if dep_cdb.found()
  summary('CDB version', dep_cdb.version(), bool_yn: true, section: 'Key-Value')
endif
