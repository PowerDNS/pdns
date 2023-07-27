# Remote ZeroMQ Backend
# Inputs: conf
# Outputs: dep_zeromq

dep_zeromq = dependency('libzmq', required: true)
conf.set10('HAVE_LIBZMQ', dep_zeromq.found(), description: 'Whether we have libzmq')
conf.set10('REMOTEBACKEND_ZEROMQ', dep_zeromq.found(), description: 'Whether we have ZeroMQ connector')
summary('ZeroMQ', dep_zeromq.found(), bool_yn: true, section: 'Configuration')
