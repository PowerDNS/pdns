# OpenSSL libssl
# Inputs: conf deps

opt_libssl = get_option('tls-libssl')
dep_libssl = dependency('libssl', required: opt_libssl)
deps += dep_libssl

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
    conf.set10('HAVE_' + func.to_upper(), has, description: 'Whether we have ' + func)
  endforeach
endif

has = cxx.has_header_symbol('openssl/ssl.h', 'SSL_CTX_set_min_proto_version', dependencies: dep_libssl)
conf.set10('HAVE_SSL_CTX_SET_MIN_PROTO_VERSION', has, description: 'Whether we have SSL_CTX_set_min_proto_version')

deps += dep_libssl
conf.set10('HAVE_LIBSSL', dep_libssl.found(), description: 'Whether we support OpenSSL libssl')
summary('OpenSSL libssl', dep_libssl.found(), bool_yn: dep_libssl.found() or not opt_libssl.auto(), section: 'Configuration')
