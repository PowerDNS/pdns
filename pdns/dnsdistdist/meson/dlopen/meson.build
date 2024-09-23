dep_dlopen = declare_dependency()

if not cxx.has_function('dlopen')
  dep_dlopen = dependency('dl', required: false)

  if not dep_dlopen.found()
    dep_dlopen = cxx.find_library('dl', required: true)

    if not cxx.has_function('dlopen', dependencies: dep_dlopen)
      error('Your system does not support dlopen')
    endif
  endif
endif

summary('dlopen', dep_dlopen.found(), bool_yn: true, section: 'System')
