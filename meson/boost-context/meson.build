# XXX ATM only boost context, no SystemV fallback as it is obsolete anyway

dep_boost_context = dependency('boost', modules: ['context'], required: true)
conf.set('HAVE_BOOST_CONTEXT', true)
summary('Context', dep_boost_context.found(), bool_yn: true, section: 'Boost')

