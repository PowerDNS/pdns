prefix = '''
#include <stdarg.h>
#include <stddef.h>
'''
found = cxx.has_header(
  'openssl/ecdsa.h',
  dependencies: dep_libcrypto,
  prefix: prefix,
  required: false
)

if found
  syms = [
    'NID_X9_62_prime256v1',
    'NID_secp384r1',
  ]

  foreach sym: syms
    found = cxx.has_header_symbol(
      'openssl/evp.h',
      sym,
      dependencies: dep_libcrypto,
      required: false
    )

    if not found
      break
    endif
  endforeach
endif

conf.set('HAVE_LIBCRYPTO_ECDSA', found, description: 'OpenSSL libcrypto ECDSA')
summary('OpenSSL libcrypto ECDSA', found, bool_yn: true, section: 'Crypto')
