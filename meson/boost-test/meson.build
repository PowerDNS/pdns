dep_boost_test = dependency('', required: false)
if get_option('unit-tests') or get_option('unit-tests-backends')
  dep_boost_test = dependency('boost', modules: ['unit_test_framework'], required: true)
  summary('Test', dep_boost_test.found(), bool_yn: true, section: 'Boost')
endif
