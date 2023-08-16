dep_boost = dependency('boost', version: '>= 1.42', required: true)
# Boost accumulators, as used by dnsbulktest and dnstcpbench, need 1.48+ to be compatible
# with C++11.
conf.set(
  'HAVE_BOOST_GE_148',
  dep_boost.version().version_compare('>= 1.48.0'),
  description: 'Boost version >= 1.48.0',
)
summary('Boost', dep_boost.found(), bool_yn: true, section: 'Boost')
summary('Version', dep_boost.version(), section: 'Boost')
