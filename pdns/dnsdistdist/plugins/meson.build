all_plugins = [
  'demo',
]

foreach plugin_name: all_plugins
  plugin_dep_name = 'dep_' + plugin_name

  subdir(plugin_name)

  shared_module(
    plugin_name,
    name_prefix: '',
    sources: plugin_sources,
    dependencies: plugin_deps,
    extra_files: plugin_extras,
  )

endforeach
