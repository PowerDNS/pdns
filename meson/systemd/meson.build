opt_systemd = get_option('systemd')

dep_systemd = dependency('libsystemd', required: opt_systemd)
conf.set('HAVE_SYSTEMD', dep_systemd.found(), description: 'systemd')
summary('Systemd', dep_systemd.found(), bool_yn: true, section: 'Configuration')

if dep_systemd.found()
  summary('Version', dep_systemd.version(), section: 'Systemd')
endif
