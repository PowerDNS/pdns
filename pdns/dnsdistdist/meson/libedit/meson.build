opt_libedit = get_option('libedit')
dep_libedit = dependency('libedit', required: opt_libedit)

conf.set('HAVE_LIBEDIT', dep_libedit.found(), description: 'libedit support')
summary('libedit support', dep_libedit.found(), bool_yn: true, section: 'Edit')
