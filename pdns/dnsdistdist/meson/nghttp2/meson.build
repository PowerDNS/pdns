opt_libnghttp2 = get_option('nghttp2')
dep_libnghttp2 = dependency('libnghttp2', required: opt_libnghttp2)

if dep_libnghttp2.found()
  funcs = [
    'nghttp2_check_header_value_rfc9113',
    'nghttp2_check_method',
    'nghttp2_check_path'
  ]

  foreach func: funcs
    has = cxx.has_function(func, dependencies: dep_libnghttp2)
    conf.set('HAVE_' + func.to_upper(), has, description: 'Have nghttp2 ' + func)
  endforeach
endif

conf.set('HAVE_NGHTTP2', dep_libnghttp2.found(), description: 'nghttp2')
summary('nghttp2', dep_libnghttp2.found(), bool_yn: true, section: 'DNS over HTTP/2')
