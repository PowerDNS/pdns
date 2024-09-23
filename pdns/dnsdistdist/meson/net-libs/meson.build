netlib_deps = []

variants = [
  ['inet_aton', 'resolv'],
  ['gethostbyname', 'nsl'],
  ['socket', 'socket'],
  ['gethostent', 'nsl'],
]

foreach variant: variants
  func_name = variant[0]
  lib_name = variant[1]

  found = cxx.has_function(func_name)
  if not found
    lib = cxx.find_library(lib_name, required: true)
    if not cxx.has_function(func_name, dependencies: lib)
      error('Cannot find function ' + func_name + ', searched library `' + lib_name + '`')
    endif
    netlib_deps += lib
    found = lib.name() + ' ' + lib.version()
  endif

  summary(func_name, found, bool_yn: true, section: 'Networking Functions')
endforeach

dep_netlibs = declare_dependency(dependencies: netlib_deps)

variants = [
  'recvmmsg',
  'sendmmsg',
  'accept4',
]

foreach variant: variants
  found = cxx.has_function(variant)
  define = 'HAVE_' + variant.to_upper()
  conf.set(define, found, description: 'Have ' + variant)
  summary(variant, found, bool_yn: true, section: 'Networking Functions')
endforeach

declared = cxx.has_header_symbol('ifaddrs.h', 'getifaddrs')
conf.set('HAVE_GETIFADDRS', declared, description: 'Have getifaddrs')
summary('getifaddrs', declared, bool_yn: true, section: 'Networking Functions')
