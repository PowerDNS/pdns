# Modules
all_modules = [
  'bind',
  'pipe',
  'gmysql',
  'godbc',
  'gpgsql',
  'gsqlite3',
  'ldap',
  'lua2',
  'remote',
  'tinydns',
  'geoip',
  'lmdb',
]

selected_modules = []
selected_dyn_modules = []
dep_modules = []
foreach module_name: all_modules
  module_backend_name = module_name + 'backend'
  module_dep_name = 'dep_' + module_backend_name
  module_lib_name = 'module_' + module_backend_name + '_lib'
  module_opt = get_option('module-' + module_name)
  module_resources = []

  if module_opt == 'disabled'
    continue
  endif

  subdir(module_backend_name)

  module_lib = static_library(
    module_backend_name,
    sources: module_sources,
    dependencies: module_deps,
    extra_files: module_extras,
  )

  set_variable(module_lib_name, declare_dependency(link_whole: module_lib))

  set_variable(module_dep_name, dependency('', required: false))
  if module_opt == 'static'
    set_variable(module_dep_name, get_variable(module_lib_name))
    selected_modules += module_name
  else
    shared_module(
      module_backend_name,
      link_whole: module_lib,
      name_suffix: 'so',
      install: true,
      install_dir: get_option('libdir') / 'powerdns'
    )
    selected_dyn_modules += module_name
  endif

  foreach resource: module_resources
    install_data(resource,
      install_dir: get_option('datadir') / 'powerdns'
    )
  endforeach

  dep_modules += get_variable(module_dep_name)
endforeach

conf.set_quoted('PDNS_MODULES', ' '.join(selected_modules), description: 'Built-in modules')
conf.set_quoted('PDNS_DYN_MODULES', ' '.join(selected_dyn_modules), description: 'Loadable modules')
