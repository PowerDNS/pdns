dep_boost_context = dependency('boost', modules: ['context'], required: true)
# Fixed value, we no longer support SystemV
conf.set('HAVE_BOOST_CONTEXT', true)
summary('Context', dep_boost_context.found(), bool_yn: true, section: 'Boost')

