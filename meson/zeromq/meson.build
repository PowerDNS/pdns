dep_zeromq = dependency('', required: false)

if get_option('module-remote') != 'disabled' and get_option('module-remote-zeromq')
  dep_zeromq = dependency('libzmq', required: true)
endif

conf.set('HAVE_LIBZMQ', dep_zeromq.found(), description: 'Have libzmq')
conf.set('REMOTEBACKEND_ZEROMQ', dep_zeromq.found(), description: 'Have ZeroMQ connector')

have_zmq_msg_send = cxx.has_function('zmq_msg_send', dependencies: dep_zeromq)
conf.set('HAVE_ZMQ_MSG_SEND', have_zmq_msg_send, description: 'Have zmq_msg_send')

summary('ZeroMQ', dep_zeromq.found(), bool_yn: true, section: 'ZeroMQ')

if dep_zeromq.found()
  summary('Version', dep_zeromq.version(), bool_yn: true, section: 'ZeroMQ')
endif
