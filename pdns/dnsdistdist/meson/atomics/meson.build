dep_atomics = dependency('', required: false)
need_latomic = false

fs = import('fs')
prog = fs.read('atomic_add_fetch.cc')
if not cxx.links(prog, name: '-latomic is not needed for using __atomic builtins')
  lib_atomic = cxx.find_library('atomic', disabler: true, required: false)
  if lib_atomic.found()
    if cxx.links(prog, name: '-latomic is needed for using __atomic builtins', dependencies: lib_atomic)
      need_latomic = true
      dep_atomics = declare_dependency(dependencies: lib_atomic)
      summary('Atomics Library', lib_atomic, section: 'System')
    else
      error('libatomic is needed and was found, but linking with it failed')
    endif
  else
    error('libatomic is needed but could not be found')
  endif
else
  dep_atomics = declare_dependency()
endif

summary('Need -latomic', need_latomic, bool_yn: true, section: 'System')
