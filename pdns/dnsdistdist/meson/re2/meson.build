opt_libre2 = get_option('re2')
dep_libre2 = dependency('re2', required: opt_libre2)

if dep_libre2.found()
    # we need to NOT pick the CFLAGS because re2 "helpfully" puts -std=c++11 here
    dep_libre2 = dep_libre2.partial_dependency(
        link_args: true
    )
endif

conf.set('HAVE_RE2', dep_libre2.found(), description: 're2')
summary('Re2', dep_libre2.found(), bool_yn: true, section: 're2')
