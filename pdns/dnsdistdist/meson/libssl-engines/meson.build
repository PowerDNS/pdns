opt_libssl_engines = get_option('tls-libssl-engines')

if opt_libssl_engines
  opt_libssl = get_option('tls-libssl')
  if not opt_libssl.allowed()
    error('OpenSSL TLS engines requested but libssl is not enabled')
  endif

  summary('OpenSSL libssl engines', true, bool_yn: true, section: 'Crypto')
else
  conf.set('OPENSSL_NO_ENGINE', true, description: 'OpenSSL libssl engines')
  summary('OpenSSL libssl engines', false, bool_yn: true, section: 'Crypto')
endif
