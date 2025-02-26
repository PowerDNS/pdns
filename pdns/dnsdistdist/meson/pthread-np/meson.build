funcs = [
  'pthread_setaffinity_np',
  'pthread_getattr_np',
  'pthread_get_stackaddr_np',
  'pthread_get_stacksize_np',
]

foreach func: funcs
  found = cxx.has_function(func, dependencies: dep_threads)
  define = 'HAVE_' + func.to_upper()
  conf.set(define, found, description: 'Have ' + func)
  summary(func, found, bool_yn: true, section: 'POSIX Threads')
endforeach
