found = cxx.has_function('clock_gettime')
dep_rt = dependency('', required: false)

if not found
  dep_rt = cxx.find_library('rt', required: true)
  found = cxx.has_function('clock_gettime', dependencies: dep_rt)
endif

conf.set('HAVE_CLOCK_GETTIME', found, description: 'Have clock_gettime')
summary('clock_gettime', true, bool_yn: true, section: 'System')

if dep_rt.found()
  summary('rt library', dep_rt.name(), bool_yn: true, section: 'System')
  summary('rt library version', dep_rt.version(), bool_yn: true, section: 'System')
endif
