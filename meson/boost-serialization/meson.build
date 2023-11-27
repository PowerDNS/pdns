dep_boost_serialization = dependency('', required: false)

if get_option('module-lmdb') != 'disabled'
  dep_boost_serialization = dependency('boost', modules: ['serialization'], required: true)
endif

summary('Serialization (LMDB)', dep_boost_serialization.found(), bool_yn: true, section: 'Boost')
