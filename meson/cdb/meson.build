dep_cdb = dependency('', required: false)

if get_option('module-tinydns') != 'disabled'
  dep_cdb = dependency('libcdb', required: false)

  if not dep_cdb.found()
    if cxx.has_header('cdb.h', required: true)
      if cxx.has_function('cdb_find', args: ['-lcdb'])
        dep_cdb = declare_dependency(link_args: ['-lcdb'])
      endif
    endif
  endif
endif

conf.set('HAVE_CDB', dep_cdb.found(), description: 'Whether we have CDB')

summary('CDB', dep_cdb.found(), bool_yn: true, section: 'CDB')

if dep_cdb.found()
  summary('Version', dep_cdb.version(), bool_yn: true, section: 'CDB')
endif
