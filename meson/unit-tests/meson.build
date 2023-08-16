opt_unittests = get_option('unit-tests')
dep_unittests = dependency('', required: false)

conf.set('UNIT_TESTS', opt_unittests, description: 'Unit tests')

if opt_unittests
  dep_boost_test = dependency('boost', modules: ['unit_test_framework'], required: true)
  summary('Test', dep_boost_test.found(), bool_yn: true, section: 'Boost')
  dep_unittests = declare_dependency(dependencies: dep_boost_test)
endif
