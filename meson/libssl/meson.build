opt_libssl = get_option('tls-libssl')
opt_libssl_dir = get_option('tls-libssl-dir')


if opt_libssl_dir != ''
  dep_libssl = declare_dependency(
    dependencies: [dep_libcrypto],
    include_directories: [opt_libssl_dir / 'include'],
    link_args: ['-L' + opt_libssl_dir / 'lib', '-lssl'],
  )
else
  dep_libssl = dependency('libssl', required: opt_libssl)
endif

if dep_libssl.found()
  funcs = [
    'SSL_CTX_set_ciphersuites',
    'SSL_CTX_set_num_tickets',
    'SSL_CTX_set_keylog_callback',
    'SSL_CTX_get0_privatekey',
    'SSL_set_hostflags',
    'SSL_CTX_set_alpn_protos',
    'SSL_CTX_set_next_proto_select_cb',
    'SSL_get0_alpn_selected',
    'SSL_get0_next_proto_negotiated',
    'SSL_CTX_set_alpn_select_cb',
    'SSL_CTX_use_cert_and_key',
  ]

  foreach func: funcs
    has = cxx.has_function(func, dependencies: dep_libssl)
    conf.set('HAVE_' + func.to_upper(), has, description: 'Have OpenSSL libssl ' + func)
  endforeach

  has = cxx.has_header_symbol(
    'openssl/ssl.h',
    'SSL_CTX_set_min_proto_version',
    dependencies: dep_libssl,
  )
  conf.set(
    'HAVE_SSL_CTX_SET_MIN_PROTO_VERSION',
    has,
    description: 'Have OpenSSL libssl SSL_CTX_set_min_proto_version',
  )
endif

conf.set('HAVE_LIBSSL', dep_libssl.found(), description: 'OpenSSL libssl')
summary('OpenSSL libssl', dep_libssl.found(), bool_yn: true, section: 'Crypto')
