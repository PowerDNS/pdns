# Auth Backend Unit Tests
# Inputs: conf deps

opt_backend_unittests = get_option('unit-tests-backends')
dep_boost_test = dependency('boost', modules: ['unit_test_framework'], required: opt_backend_unittests)
deps += dep_boost_test
conf.set10('BACKEND_UNIT_TESTS', opt_backend_unittests, description: 'Whether backend unit tests are enabled')
if not opt_unittests
  summary('Test', dep_boost_test.found(), bool_yn: true, section: 'Boost')
endif
