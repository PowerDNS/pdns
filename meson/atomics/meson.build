# Atomics
# Inputs: deps

prog = '''
#include <stdint.h>

int main() {
  uint64_t val = 0;
  __atomic_add_fetch(&val, 1, __ATOMIC_RELAXED);
  return 0;
}
'''

need_latomic = false

if not cxx.links(prog, name: '-latomic is not needed for using __atomic builtins')
  atomic = cxx.find_library('atomic', disabler: true, required: false)
  if atomic.found()
    if cxx.links(prog, name: '-latomic is needed for using __atomic builtins', dependencies: atomic)
      need_latomic = true
      summary('Atomics Library', atomic, section: 'System')
      deps += atomic
    else
      error('libatomic needed but could not be found')
    endif
  else
    error('libatomic needed and was found, but linking with it failed')
  endif
endif

summary('Need -latomic', need_latomic, section: 'System')
