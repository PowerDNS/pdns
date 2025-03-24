opt_dot = get_option('dns-over-tls')

if opt_dot.enabled() and not dep_libssl.found() and not dep_gnutls.found()
  error('DNS over TLS support was requested but neither OpenSSL libssl nor GnuTLS support is enabled')
endif

conf.set('HAVE_DNS_OVER_TLS', opt_dot.allowed() and (dep_libssl.found() or dep_gnutls.found()), description: 'DNS over TLS (DoT)')
summary('DNS over TLS', opt_dot.allowed() and (dep_libssl.found() or dep_gnutls.found()), bool_yn: true, section: 'Configuration')
