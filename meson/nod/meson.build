opt_nod = get_option('nod')

if not dep_boost_filesystem.found() and opt_nod
  error('NOD support was requested but boost filesystem module not found')
endif

enable_nod = dep_boost_filesystem.found() and opt_nod
dep_nod = declare_dependency(
      dependencies: [dep_boost_filesystem, dep_probds],
) 

conf.set('NOD_ENABLED', enable_nod, description: 'NOD')
summary('NOD', enable_nod, bool_yn: true, section: 'Configuration')
