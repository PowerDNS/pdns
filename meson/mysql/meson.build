dep_mysql = dependency('', required: false)

if get_option('module-gmysql') != 'disabled'
  dep_mysql = dependency('libmysql', required: false)
  if not dep_mysql.found()
    dep_mysql = dependency('libmariadb', required: false)
  endif

  if not dep_mysql.found()
    mysql_config = find_program('mysql_config', required: false)
    if not mysql_config.found()
      mysql_config = find_program('mariadb_config', required: true)
    endif

    mysql_cflags_res = run_command(mysql_config, '--cflags', check: true)
    mysql_cflags = mysql_cflags_res.stdout().strip().split()

    mysql_ldflags_res = run_command(mysql_config, '--libs', check: true)
    mysql_ldflags = mysql_ldflags_res.stdout().strip().split()

    mysql_version_res = run_command(mysql_config, '--version', check: false)
    mysql_version = mysql_version_res.stdout().strip()

    dep_mysql = declare_dependency(
      compile_args: mysql_cflags,
      link_args: mysql_ldflags,
      version: mysql_version,
    )
  endif
endif

summary('MySQL/MariaDB', dep_mysql.found(), bool_yn: true, section: 'MySQL')

if dep_mysql.found()
  summary('Version', dep_mysql.version(), section: 'MySQL')
endif
