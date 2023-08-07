# GnuTLS
# Inputs: conf deps

opt_gnutls = get_option('tls-gnutls')
dep_gnutls = dependency('gnutls', version: '>= 3.1.11', required: opt_gnutls)

if dep_gnutls.found()
  funcs = [
    'gnutls_memset',
    'gnutls_session_set_verify_cert',
    'gnutls_session_get_verify_cert_status',
    'gnutls_alpn_set_protocols',
  ]

  foreach func: funcs
    has = cxx.has_function(func, dependencies: dep_gnutls)
    conf.set10('HAVE_' + func.to_upper(), has, description: 'Whether we have ' + func)
  endforeach
endif

deps += dep_gnutls
conf.set10('HAVE_GNUTLS', dep_gnutls.found(), description: 'Whether we support GnuTLS')
summary('GnuTLS', dep_gnutls.found(), bool_yn: dep_gnutls.found() or not opt_gnutls.auto(), section: 'Configuration')
