syms = [
  'ED25519',
  'ED448',
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

conf.set('HAVE_LIBCRYPTO_EDDSA', found, description: 'OpenSSL EdDSA support')
summary('OpenSSL libcrypto EdDSA', found, bool_yn: true, section: 'Crypto')
