opt_systemd = get_option('systemd')

dep_systemd = dependency('libsystemd', required: opt_systemd)
conf.set('HAVE_SYSTEMD', dep_systemd.found(), description: 'libsystemd')
summary('libsystemd', dep_systemd.found(), bool_yn: true, section: 'Configuration')

if dep_systemd.found()
  summary('Lib Version', dep_systemd.version(), section: 'Systemd')
endif
