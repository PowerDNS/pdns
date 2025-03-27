opt_doh3 = get_option('dns-over-http3')

if opt_doh3.enabled()
  if not dep_libquiche.found()
    error('DNS over HTTP/3 support was requested but Quiche support is not enabled')
  endif
endif

conf.set('HAVE_DNS_OVER_HTTP3', opt_doh3.allowed() and dep_libquiche.found(), description: 'DNS over HTTP/3 (DoH3)')
summary('DNS over HTTP/3', opt_doh3.allowed() and dep_libquiche.found(), bool_yn: true, section: 'Configuration')
