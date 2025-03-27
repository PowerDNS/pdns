funcs = [
  'localtime_r',
  'gmtime_r',
  'recvmmsg',
  'sched_setscheduler',
  'getrandom',
  'arc4random',
  'getentropy',
  'arc4random_uniform',
  'arc4random_buf',
  'explicit_bzero',
  'explicit_memset',
  'memset_s',
]

foreach func: funcs
  found = cxx.has_function(func)
  define = 'HAVE_' + func.to_upper()
  conf.set(define, found, description: 'Have ' + func)
  summary(func, found, bool_yn: true, section: 'Various Functions')
endforeach
