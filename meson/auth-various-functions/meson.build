# Various Functions

funcs = [
  'strcasestr',
  'localtime_r',
  'gmtime_r',
  'recvmmsg',
  'sched_setscheduler',
  'getrandom',
  'arc4random',
]
foreach func: funcs
  found = cxx.has_function(func)
  define = 'HAVE_' + func.to_upper()
  conf.set10(define, found, description: 'Whether we have ' + func)
  summary(func, found, bool_yn: true, section: 'Various Functions')
endforeach
