dep_boost = dependency('boost', version: '>= 1.42', required: true)
# Boost accumulators, as used by dnsbulktest and dnstcpbench, need 1.48+ to be compatible
# with C++11.
have_boost_1_48_0 = dep_boost.version().version_compare('>= 1.48.0')
conf.set('HAVE_BOOST_GE_148', have_boost_1_48_0, description: 'Boost version >= 1.48.0')
# conf.set('BOOST_CONTAINER_USE_STD_EXCEPTIONS', true, description: 'Boost use std exceptions')
add_project_arguments('-DBOOST_CONTAINER_USE_STD_EXCEPTIONS', language: ['c', 'cpp'])
summary('Boost', dep_boost.found(), bool_yn: true, section: 'Boost')
summary('Version', dep_boost.version(), section: 'Boost')
