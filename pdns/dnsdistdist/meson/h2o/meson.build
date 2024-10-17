opt_h2o = get_option('h2o')
dep_libh2o_evloop = dependency('libh2o-evloop', required: opt_h2o)

if dep_libh2o_evloop.found()
  funcs = [
    'h2o_socket_get_ssl_server_name',
  ]

  foreach func: funcs
    has = cxx.has_function(func, dependencies: dep_libh2o_evloop)
    conf.set('HAVE_' + func.to_upper(), has, description: 'Have h2o ' + func)
  endforeach
endif

conf.set('HAVE_LIBH2OEVLOOP', dep_libh2o_evloop.found(), description: 'H2O library with event loop support for DNS over HTTP/2')
summary('H2O library with event loop support for DNS over HTTP/2', dep_libh2o_evloop.found(), bool_yn: true, section: 'DNS over HTTP/2')
