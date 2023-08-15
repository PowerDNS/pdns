dep_systemd = dependency('libsystemd', required: false)
conf.set('HAVE_SYSTEMD', dep_systemd.found(), description: 'systemd')
summary('Systemd', dep_systemd.found(), bool_yn: true, section: 'Configuration')

if dep_systemd.found()
  summary('Version', dep_systemd.version(), section: 'Systemd')

  systemd_service_user = get_option('systemd-service-user')
  systemd_service_group = get_option('systemd-service-group')

  summary('Service User', systemd_service_user, section: 'Systemd')
  summary('Service Group', systemd_service_group, section: 'Systemd')
endif
