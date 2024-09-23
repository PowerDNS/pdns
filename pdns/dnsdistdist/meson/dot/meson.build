opt_dot = get_option('dns-over-tls')
conf.set('HAVE_DNS_OVER_TLS', opt_dot, description: 'DNS over TLS (DoT)')

if opt_dot and not dep_libssl.found() and not dep_gnutls.found()
  error('DNS over TLS support was requested but neither OpenSSL libssl nor GnuTLS support is enabled')
endif

summary('DNS over TLS', opt_dot, bool_yn: true, section: 'Configuration')
