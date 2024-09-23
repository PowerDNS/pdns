opt_doh2 = get_option('dns-over-https')
conf.set('HAVE_DNS_OVER_HTTPS', opt_doh2, description: 'DNS over HTTP/2 (DoH)')

if opt_doh2
  if not dep_libssl.found() and not dep_gnutls.found()
    error('DNS over HTTP/2 support was requested but neither OpenSSL libssl nor GnuTLS support is enabled')
  endif
  if not dep_libnghttp2.found() and not dep_libh2o_evloop.found()
    error('DNS over HTTP/2 support was requested but neither nghttp2 not libh2o-evloop support is enabled')
  endif
endif

summary('DNS over HTTP/2', opt_doh2, bool_yn: true, section: 'Configuration')
