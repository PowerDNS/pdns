opt_doh2 = get_option('dns-over-https')

if opt_doh2.enabled()
  if not dep_libssl.found() and not dep_gnutls.found()
    error('DNS over HTTP/2 support was requested but neither OpenSSL libssl nor GnuTLS support is enabled')
  endif
  if not dep_libnghttp2.found()
    error('DNS over HTTP/2 support was requested but nghttp2 support is enabled')
  endif
endif

conf.set('HAVE_DNS_OVER_HTTPS', opt_doh2.allowed() and (dep_libssl.found() or dep_gnutls.found()) and (dep_libnghttp2.found()), description: 'DNS over HTTP/2 (DoH)')
summary('DNS over HTTP/2', opt_doh2.allowed() and (dep_libssl.found() or dep_gnutls.found()) and (dep_libnghttp2.found()), bool_yn: true, section: 'Configuration')
