# Libcrypto EdDSA signers
# Inputs: libcrypto_args libcrypto_incs dep_libcrypto conf

syms = ['ED25519', 'ED448']
found = false
foreach sym: syms
  res = cxx.has_header_symbol('openssl/evp.h', 'NID_' + sym, args: libcrypto_args, include_directories: libcrypto_incs, dependencies: dep_libcrypto, required: false)
  if res
    found = true
    conf.set10('HAVE_LIBCRYPTO_' + sym, true, description: 'Whether we have OpenSSL libcrypto ' + sym + ' support')
  endif

  summary(sym, res, bool_yn: res or opt_libcrypto != 'auto', section: 'OpenSSL libcrypto Features')
endforeach

conf.set10('HAVE_LIBCRYPTO_EDDSA', found, description: 'Whether we have OpenSSL EdDSA support')
summary('EdDSA', found, bool_yn: found or opt_libcrypto != 'auto', section: 'OpenSSL libcrypto Features')
