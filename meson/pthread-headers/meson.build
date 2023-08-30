dep_threads = dependency('threads')

have_pthread_h = cxx.check_header(
  'pthread.h',
  dependencies: dep_threads,
  required: true,
)
have_pthread_np_h = cxx.check_header(
  'pthread_np.h',
  dependencies: dep_threads,
  prefix: '#include <pthread.h>',
)

conf.set('HAVE_PTHREAD_NP_H', have_pthread_np_h, description: 'Have <pthread_np.h>')

summary('Threads', dep_threads.found(), bool_yn: true, section: 'POSIX Threads')
summary('Have <pthread.h>', have_pthread_h, bool_yn: true, section: 'POSIX Threads')
summary('Have <pthread_np.h>', have_pthread_np_h, bool_yn: true, section: 'POSIX Threads')
