opt_systemd = get_option('systemd-service')

dep_systemd_prog = dependency('systemd', required: opt_systemd)
summary('Systemd', dep_systemd_prog.found(), bool_yn: true, section: 'Configuration')

# Map systemd features to systemd/systemctl version.
systemd_features = {
  'private_tmp': 183,
  'system_call_architectures': 209,
  'private_devices': 209,
  'restrict_address_families': 211,
  'protect_system': 214,
  'protect_home': 214,
  'restrict_realtime': 231,
  'memory_deny_write_execute': 231,
  'protect_control_groups': 232,
  'protect_kernel_modules': 232,
  'protect_kernel_tunables': 232,
  'remove_ipc': 232,
  'dynamic_user': 232,
  'private_users': 232,
  'protect_system_strict': 232,
  'restrict_namespaces': 233,
  'lock_personality': 235,
  # while SystemCallFilter is technically available starting with 187,
  # we use the pre-defined call filter sets that have been introduced later.
  # Initial support for these landed in 231
  # @filesystem @reboot @swap in 233
  # @aio, @sync, @chown, @setuid, @memlock, @signal and @timer in 235
  'system_call_filter': 235,
  'percent_t': 236,
  'private_mounts': 239,
  'with_runtime_dir_env': 240,
  'protect_hostname': 242,
  'restrict_suidsgid': 242,
  'protect_kernel_logs': 244,
  'protect_clock': 245,
  'protect_proc': 247,
  'private_ipc': 248,
}

systemd_version = dep_systemd_prog.version()
foreach feature, version: systemd_features
  feature_name = 'have_systemd_' + feature
  feature_value = systemd_version.version_compare('>=' + version.to_string())
  set_variable(feature_name, feature_value)
  conf.set(feature_name.to_upper(), feature_value, description: 'systemd feature: ' + feature)
endforeach

if dep_systemd_prog.found()
  summary('Version', dep_systemd_prog.version(), section: 'Systemd')
endif
