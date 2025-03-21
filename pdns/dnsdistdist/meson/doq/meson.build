opt_doq = get_option('dns-over-quic')

if opt_doq.enabled()
  if not dep_libquiche.found()
    error('DNS over QUIC support was requested but Quiche support is not enabled')
  endif
endif

if opt_doq.allowed() and dep_libquiche.found()
  conf.set('HAVE_DNS_OVER_QUIC', true, description: 'DNS over QUIC (DoQ)')
  summary('DNS over QUIC', true, bool_yn: true, section: 'Configuration')
else
  summary('DNS over QUIC', false, bool_yn: true, section: 'Configuration')
endif
