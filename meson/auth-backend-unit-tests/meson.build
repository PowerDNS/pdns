opt_backend_unittests = get_option('unit-tests-backends')
dep_backend_unittests = dependency('', required: false)

conf.set('BACKEND_UNIT_TESTS', opt_backend_unittests, description: 'Backend unit tests')

if opt_backend_unittests
  dep_boost_test = dependency('boost', modules: ['unit_test_framework'], required: true)

  if not dep_unittests.found()
    summary('Test', dep_boost_test.found(), bool_yn: true, section: 'Boost')
  endif

  dep_backend_unittests = declare_dependency(dependencies: dep_boost_test)
endif
