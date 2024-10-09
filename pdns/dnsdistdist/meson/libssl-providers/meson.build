opt_libssl_providers = get_option('tls-libssl-providers')

if opt_libssl_providers
  opt_libssl = get_option('tls-libssl')
  if not opt_libssl.allowed()
    error('OpenSSL TLS providers requested but libssl is not enabled')
  endif
  dep_libssl_3_later = dependency('libssl >= 3.0', required: false)

  if not dep_libssl_3_later.found()
    error('OpenSSL TLS providers requested but libssl is not >= 3.0')
  endif

  conf.set('HAVE_TLS_PROVIDERS', dep_libssl_3_later.found(), description: 'OpenSSL libssl providers')
  summary('OpenSSL libssl providers', dep_libssl_3_later.found(), bool_yn: true, section: 'Crypto')
endif
