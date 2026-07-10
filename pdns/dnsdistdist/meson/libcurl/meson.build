opt_otlp = get_option('otlp')
opt_libcurl = get_option('libcurl')

if opt_otlp.allowed() and opt_libcurl.allowed()
  dep_libcurl = dependency('libcurl', version: '>= 7.21.3', required: false)
else
  dep_libcurl = dependency('', required: false)
endif

conf.set('HAVE_LIBCURL', dep_libcurl.found(), description: 'Whether we have libcurl')
summary('cURL', dep_libcurl.found(), bool_yn: true, section: 'Configuration')
summary('OTLP remote logger', dep_libcurl.found() and opt_otlp.allowed(), bool_yn: true, section: 'Configuration')
