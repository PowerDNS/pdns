opt_systemd = get_option('systemd-service')

dep_libsystemd = dependency('libsystemd', required: opt_systemd)
conf.set('HAVE_SYSTEMD', dep_libsystemd.found(), description: 'libsystemd')
summary('libsystemd', dep_libsystemd.found(), bool_yn: true, section: 'Configuration')

if dep_libsystemd.found()
  summary('Lib Version', dep_libsystemd.version(), section: 'Systemd')
endif
