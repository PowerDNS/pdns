opt_doq = get_option('dns-over-quic')

if opt_doq.enabled()
  if not dep_libquiche.found()
    error('DNS over QUIC support was requested but Quiche support is not enabled')
  endif
endif

conf.set('HAVE_DNS_OVER_QUIC', opt_doq.allowed() and dep_libquiche.found(), description: 'DNS over QUIC (DoQ)')
summary('DNS over QUIC', opt_doq.allowed() and dep_libquiche.found(), bool_yn: true, section: 'Configuration')
