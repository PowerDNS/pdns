dep_odbc = dependency('', required: false)

if get_option('module-godbc') != 'disabled'
  dep_odbc = dependency('odbc', required: false)

  if not dep_odbc.found()
    odbc_config = find_program('odbc_config', required: true)

    odbc_cflags_res = run_command(odbc_config, '--cflags', check: true)
    odbc_cflags = odbc_cflags_res.stdout().strip().split()

    odbc_ldflags_res = run_command(odbc_config, '--libs', check: true)
    odbc_ldflags = odbc_ldflags_res.stdout().strip().split()

    odbc_version_res = run_command(odbc_config, '--version', check: true)
    odbc_version = odbc_version_res.stdout().strip()

    dep_odbc = declare_dependency(
      compile_args: odbc_cflags,
      link_args: odbc_ldflags,
      version: odbc_version,
    )
  endif
endif

summary('ODBC', dep_odbc.found(), bool_yn: true, section: 'ODBC')

if dep_odbc.found()
  summary('Version', dep_odbc.version(), section: 'ODBC')
endif
