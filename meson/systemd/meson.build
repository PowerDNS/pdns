# Systemd and unit file handling
# Inputs: conf
# Outputs: dep_systemd

dep_systemd = dependency('systemd', required: false)
conf.set10('HAVE_SYSTEMD', dep_systemd.found(), description: 'Whether we have systemd')
summary('Systemd', dep_systemd.found(), bool_yn: true, section: 'Configuration')

if dep_systemd.found()
  summary('Systemd Version', dep_systemd.version(), section: 'Configuration')

  systemd_service_user = get_option('systemd-service-user')
  systemd_service_group = get_option('systemd-service-group')

  summary('Systemd User', systemd_service_user, section: 'Configuration')
  summary('Systemd Group', systemd_service_group, section: 'Configuration')
endif
