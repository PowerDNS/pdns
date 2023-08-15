# PostgreSQL
# Outputs: deps_pgsql

deps_pgsql = dependency('libpq', required: false)

if not deps_pgsql.found()
  pg_config = find_program('pg_config', required: true)

  pg_cflags_res = run_command(pg_config, '--cflags', check: true)
  pg_cflags = pg_cflags_res.stdout().strip().split()

  pg_cppflags_res = run_command(pg_config, '--cppflags', check: true)
  pg_cppflags = pg_cppflags_res.stdout().strip().split()

  pg_ldflags_res = run_command(pg_config, '--libs', check: true)
  pg_ldflags = pg_ldflags_res.stdout().strip().split()

  pg_version_res = run_command(pg_config, '--version', check: true)
  pg_version = pg_version_res.stdout().strip().split()[1]

  deps_pgsql = declare_dependency(compile_args: pg_cflags + pg_cppflags, link_args: pg_ldflags, version: pg_version)
endif

summary('PostgreSQL', deps_pgsql.found(), bool_yn: true, section: 'Configuration')
summary('PostgreSQL Version', deps_pgsql.version(), section: 'Configuration')