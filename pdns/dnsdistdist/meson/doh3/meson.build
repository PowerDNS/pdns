opt_doh3 = get_option('dns-over-http3')
conf.set('HAVE_DNS_OVER_HTTP3', opt_doh3, description: 'DNS over HTTP/3 (DoH3)')

if opt_doh3
  if not dep_libquiche.found()
    error('DNS over HTTP/3 support was requested but Quiche support is not enabled')
  endif
endif

summary('DNS over HTTP/3', opt_doh3, bool_yn: true, section: 'Configuration')
