opt_mmdb = get_option('mmdb')
dep_mmdb = dependency('libmaxminddb', required: opt_mmdb)

if opt_mmdb.allowed()
  if not dep_mmdb.found()
    if cxx.has_header('maxminddb.h', required: false)
      if cxx.has_function('MMDB_open', args: ['-lmaxminddb'])
        dep_mmdb = declare_dependency(link_args: ['-lmaxminddb'])
      endif
    endif
  endif
endif

conf.set('HAVE_MMDB', dep_mmdb.found(), description: 'Whether we have MMDB')
summary('MMDB', dep_mmdb.found(), bool_yn: true, section: 'Key-Value')
if dep_mmdb.found()
  summary('MMDB version', dep_mmdb.version(), bool_yn: true, section: 'Key-Value')
endif
