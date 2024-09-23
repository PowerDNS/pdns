opt_libre2 = get_option('re2')
dep_libre2 = dependency('re2', required: opt_libre2)

conf.set('HAVE_RE2', dep_libre2.found(), description: 're2')
summary('Re2', dep_libre2.found(), bool_yn: true, section: 're2')
