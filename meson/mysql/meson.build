# MySQL
# Outputs: deps_mysql

deps_mysql = dependency('libmysql', required: false)
if not deps_mysql.found()
  deps_mysql = dependency('libmariadb', required: false)
endif

if not deps_mysql.found()
  mysql_config = find_program('mysql_config', required: false)
  if not mysql_config.found()
    mysql_config = find_program('mariadb_config', required: true)
  endif

  mysql_cflags_res = run_command(mysql_config, '--cflags', check: true)
  mysql_cflags = mysql_cflags_res.stdout().strip().split()

  mysql_ldflags_res = run_command(mysql_config, '--libs', check: true)
  mysql_ldflags = mysql_ldflags_res.stdout().strip().split()

  mysql_version_res = run_command(mysql_config, '--cc_version', check: true)
  mysql_version = mysql_version_res.stdout().strip()

  deps_mysql = declare_dependency(compile_args: mysql_cflags, link_args: mysql_ldflags, version: mysql_version)
endif

summary('MySQL/MariaDB', deps_mysql.found(), bool_yn: true, section: 'Configuration')
summary('MySQL/MariaDB Version', deps_mysql.version(), section: 'Configuration')