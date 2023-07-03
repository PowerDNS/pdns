# libcrypto ECDSA signers
# Inputs: libcrypto_incs libcrypto_args dep_libcrypto conf

found = cxx.has_header('openssl/ecdsa.h', args: libcrypto_args, include_directories: libcrypto_incs, dependencies: dep_libcrypto, prefix: prefix, required: false)

if found
  syms = ['NID_X9_62_prime256v1', 'NID_secp384r1']
  foreach sym: syms
    if not cxx.has_header_symbol('openssl/evp.h', sym, args: libcrypto_args, include_directories: libcrypto_incs, dependencies: dep_libcrypto, required: false)
      found = false
      break
    endif
  endforeach
endif

conf.set10('HAVE_LIBCRYPTO_ECDSA', found, description: 'Whether we have OpenSSL libcrypto ECDSA support')
summary('ECDSA', found, bool_yn: found or opt_libcrypto != 'auto', section: 'OpenSSL libcrypto Features')
