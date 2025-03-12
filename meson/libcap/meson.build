opt_libcap = get_option('libcap')
dep_libcap = dependency('libcap', required: opt_libcap)

conf.set('HAVE_LIBCAP', dep_libcap.found(), description: 'libcap support')
summary('libcap support', dep_libcap.found(), bool_yn: true, section: 'Capabilities')
