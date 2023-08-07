# Libsodium-based signers
# Inputs: deps conf

opt_libsodium = get_option('signers-libsodium')
dep_libsodium = dependency('libsodium', required: opt_libsodium, not_found_message: 'libsodium not found')

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
    has = cxx.has_function(func, dependencies: dep_libsodium)
    conf.set10(define, has, description: 'Whether we have ' + func)
    # summary(func, has, bool_yn: true, section: 'Libsodium Functions')
  endforeach
endif

deps += dep_libsodium
conf.set10('HAVE_LIBSODIUM', dep_libsodium.found(), description: 'Whether we build libsodium-based signers')
summary('libsodium', dep_libsodium.found(), bool_yn: true, section: 'Configuration')
