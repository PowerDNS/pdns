opt_dnstap = get_option('dnstap')
dep_dnstap = dependency('libfstrm', required: opt_dnstap)

if dep_dnstap.found()
  funcs = [
    'fstrm_tcp_writer_init',
  ]

  foreach func: funcs
    has = cxx.has_function(func, dependencies: dep_dnstap)
    conf.set('HAVE_' + func.to_upper(), has, description: 'Have libfstram ' + func)
  endforeach
endif

conf.set('HAVE_FSTRM', dep_dnstap.found(), description: 'libfstrm')
summary('DNSTAP', dep_dnstap.found(), bool_yn: true, section: 'Configuration')
