opt_zeromq = get_option('module-remote-zeromq')

dep_zeromq = dependency('', required: false)
if opt_zeromq
  dep_zeromq = dependency('libzmq', required: opt_zeromq)
endif

conf.set('HAVE_LIBZMQ', dep_zeromq.found(), description: 'Have libzmq')
conf.set('REMOTEBACKEND_ZEROMQ', dep_zeromq.found(), description: 'Have ZeroMQ connector')
summary('ZeroMQ', dep_zeromq.found(), bool_yn: true, section: 'ZeroMQ')

if dep_zeromq.found()
  summary('Version', dep_zeromq.version(), bool_yn: true, section: 'ZeroMQ')
endif
