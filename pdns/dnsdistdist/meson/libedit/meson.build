opt_libedit = get_option('libedit')
dep_libedit = dependency('libedit', required: false)

if not dep_libedit.found()
  dep_libedit = cxx.find_library('edit', required: opt_libedit)
endif

conf.set('HAVE_LIBEDIT', dep_libedit.found(), description: 'libedit support')
summary('libedit support', dep_libedit.found(), bool_yn: true, section: 'Edit')
