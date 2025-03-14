opt_systemd = get_option('systemd-service')

dep_libsystemd = dependency('', required: false)

if opt_systemd.allowed()
  dep_libsystemd = dependency('libsystemd', required: opt_systemd)
endif

conf.set('HAVE_SYSTEMD', dep_libsystemd.found(), description: 'libsystemd')
if dep_libsystemd.found()
  summary('Lib Version', dep_libsystemd.version(), section: 'Systemd')
endif

summary('libsystemd', dep_libsystemd.found(), bool_yn: true, section: 'Configuration')
