opt_libsodium = get_option('libsodium')
dep_libsodium = dependency('libsodium', required: opt_libsodium)

if dep_libsodium.found()
  funcs = [
    'crypto_box_easy_afternm',
    'crypto_box_curve25519xchacha20poly1305_easy',
    'randombytes_stir',
    'sodium_memcmp',
    'crypto_shorthash'
  ]

  foreach func: funcs
    define = 'HAVE_' + func.to_upper()
    have_func = cxx.has_function(func, dependencies: dep_libsodium)
    conf.set(define, have_func, description: 'Have libsodium ' + func)
  endforeach
endif

conf.set('HAVE_LIBSODIUM', dep_libsodium.found(), description: 'libsodium support')
summary('libsodium support', dep_libsodium.found(), bool_yn: true, section: 'Crypto')
