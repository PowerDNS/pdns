# Check for mmap

mman_h = cxx.has_header('sys/mman.h', required: false)
have_mmap = false
if mman_h
  have_mmap = cxx.has_function('mmap', prefix: '''#include <sys/mman.h>''')
endif

conf.set10('HAVE_MMAP', have_mmap, description: 'Whether we have mmap')

summary('sys/mman.h', mman_h, bool_yn: true, section: 'System')
summary('mmap', have_mmap, bool_yn: true, section: 'System')
