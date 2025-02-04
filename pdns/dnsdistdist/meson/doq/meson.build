opt_doq = get_option('dns-over-quic')
conf.set('HAVE_DNS_OVER_QUIC', opt_doq, description: 'DNS over QUIC (DoQ)')

if opt_doq
  if not dep_libquiche.found()
    error('DNS over QUIC support was requested but Quiche support is not enabled')
  endif
endif

summary('DNS over QUIC', opt_doq, bool_yn: true, section: 'Configuration')
