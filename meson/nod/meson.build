opt_nod = get_option('nod')

if opt_nod.enabled()
  if not dep_probds.found()
    error('NOD support was requested but probds not found')
  endif
endif

enable_nod = opt_nod.allowed() and dep_probds.found()
if enable_nod
  dep_nod = declare_dependency(
    dependencies: dep_probds,
  )
else
  dep_nod = dependency('', required: false)
endif

conf.set('NOD_ENABLED', enable_nod, description: 'NOD')
summary('NOD', enable_nod, bool_yn: true, section: 'Configuration')
