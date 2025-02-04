dep_libquiche = dependency('', required: false)
opt_libquiche = get_option('quiche')

if (get_option('dns-over-quic') or get_option('dns-over-http3')) and opt_libquiche.allowed()
  dep_libquiche = dependency('quiche', version: '>= 0.23.0', required: opt_libquiche)
  if dep_libquiche.found()
    conf.set('HAVE_QUICHE_H3_EVENT_HEADERS_HAS_MORE_FRAMES', dep_libquiche.found(), description: 'if the Quiche API has quiche_h3_event_headers_has_more_frames instead of quiche_h3_event_headers_has_body')
  else
    dep_libquiche = dependency('quiche', version: '>= 0.22.0', required: opt_libquiche)
  endif

  if dep_libquiche.found()
    conf.set('HAVE_QUICHE_STREAM_ERROR_CODES', dep_libquiche.found(), description: 'if the Quiche API includes error code in quiche_conn_stream_recv and quiche_conn_stream_send')
  else
    dep_libquiche = dependency('quiche', version: '>= 0.15.0', required: opt_libquiche)
  endif
endif

conf.set('HAVE_QUICHE', dep_libquiche.found(), description: 'quiche')
summary('Quiche', dep_libquiche.found(), bool_yn: true, section: 'DNS over QUIC / HTTP3')
