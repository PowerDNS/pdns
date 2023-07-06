# Unit Tests
# Inputs: conf

opt_unittests = get_option('unit-tests')
dep_boost_test = dependency('boost', modules: ['unit_test_framework'], required: opt_unittests)
conf.set10('UNIT_TESTS', dep_boost_test.found(), description: 'Whether unit tests are enabled')
summary('Boost Test', dep_boost_test.found(), bool_yn: true, section: 'Boost')
