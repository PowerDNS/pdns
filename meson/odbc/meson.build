# ODBC
# Outputs: deps_odbc

deps_odbc = dependency('odbc', required: false)

if not deps_odbc.found()
  odbc_config = find_program('odbc_config', required: true)

  odbc_cflags_res = run_command(odbc_config, '--cflags', check: true)
  odbc_cflags = odbc_cflags_res.stdout().strip().split()

  odbc_ldflags_res = run_command(odbc_config, '--libs', check: true)
  odbc_ldflags = odbc_ldflags_res.stdout().strip().split()

  odbc_version_res = run_command(odbc_config, '--version', check: true)
  odbc_version = odbc_version_res.stdout().strip()

  deps_odbc = declare_dependency(compile_args: odbc_cflags, link_args: odbc_ldflags, version: odbc_version)
endif

summary('ODBC', deps_odbc.found(), bool_yn: true, section: 'Configuration')
summary('ODBC Version', deps_odbc.version(), section: 'Configuration')
