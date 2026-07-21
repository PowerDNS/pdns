syms = [
  'ML_DSA_44',
]

found = false
foreach sym: syms
  has = cxx.has_header_symbol(
    'openssl/evp.h',
    'NID_' + sym,
    dependencies: dep_libcrypto,
    required: false,
  )

  conf.set('HAVE_LIBCRYPTO_' + sym, has, description: 'OpenSSL libcrypto ' + sym)
  summary('OpenSSL libcrypto ' + sym, has, bool_yn: true, section: 'Crypto')

  if has
    found = true
  endif
endforeach

conf.set('HAVE_LIBCRYPTO_MLDSA', found, description: 'OpenSSL MLDSA support')
summary('OpenSSL libcrypto MLDSA', found, bool_yn: true, section: 'Crypto')
