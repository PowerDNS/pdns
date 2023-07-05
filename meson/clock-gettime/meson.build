# Clock_gettime
# Inputs: deps

found = cxx.has_function('clock_gettime')

if not found
  lib = cxx.find_library('rt', required: true)

  if not cxx.has_function('clock_gettime', dependencies: lib)
    error('Cannot find function ' + 'clock_gettime')
  endif

  deps += lib
  found = lib.name() + ' ' + lib.version()
endif

summary('clock_gettime', found, bool_yn: true, section: 'System')
