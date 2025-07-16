opt_libcurl = get_option('libcurl')
dep_libcurl = dependency('libcurl', version: '>= 7.21.3', required: opt_libcurl)
conf.set('HAVE_LIBCURL', dep_libcurl.found(), description: 'Whether we have libcurl')
summary('CURL', dep_libcurl.found(), bool_yn: true, section: 'Configuration')
