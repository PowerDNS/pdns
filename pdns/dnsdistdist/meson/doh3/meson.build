opt_doh3 = get_option('dns-over-http3')

if opt_doh3.enabled()
  if not dep_libquiche.found()
    error('DNS over HTTP/3 support was requested but Quiche support is not enabled')
  endif
endif

if opt_doh3.allowed() and dep_libquiche.found()
  conf.set('HAVE_DNS_OVER_HTTP3', true, description: 'DNS over HTTP/3 (DoH3)')
  summary('DNS over HTTP/3', true, bool_yn: true, section: 'Configuration')
else
  summary('DNS over HTTP/3', false, bool_yn: true, section: 'Configuration')
endif
