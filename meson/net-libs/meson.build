# Network Libraries ----------------------------------------------------------------------
# Inputs: deps conf

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
      error('Cannot find function ' + func_name)
    endif
    deps += lib
    found = lib.name() + ' ' + lib.version()
  endif

  # summary(func_name, found, bool_yn: true, section: 'Network Functions')
endforeach

variants = ['recvmmsg', 'sendmmsg', 'accept4']
foreach variant: variants
  found = cxx.has_function(variant)
  define = 'HAVE_' + variant.to_upper()
  conf.set10(define, found, description: 'Whether we have ' + variant)
  # summary(variant, found, bool_yn: true, section: 'Network Functions')
endforeach

declared = cxx.has_header_symbol('ifaddrs.h', 'getifaddrs')
conf.set10('HAVE_GETIFADDRS', declared, description: 'Whether we have getifaddrs')
# summary('getifaddrs', declared, bool_yn: true, section: 'Network Functions')
