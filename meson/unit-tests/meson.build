# Unit Tests
# Inputs: conf deps
# Outputs: opt_unittests

opt_unittests = get_option('unit-tests')
dep_boost_test = dependency('boost', modules: ['unit_test_framework'], required: opt_unittests)
deps += dep_boost_test
conf.set10('UNIT_TESTS', opt_unittests, description: 'Whether unit tests are enabled')
if opt_unittests
  summary('Test', dep_boost_test.found(), bool_yn: true, section: 'Boost')
endif
