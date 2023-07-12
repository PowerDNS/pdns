# SQLite3
# Outputs: deps_sqlite3

deps_sqlite3 = dependency('sqlite3', required: true)

conf.set10('HAVE_SQLITE3', deps_sqlite3.found(), description: 'Whether we have Sqlite3')
conf.set10('SQLITE3', deps_sqlite3.found(), description: 'Whether we have Sqlite3')
summary('SQLite3', deps_sqlite3.found(), bool_yn: true, section: 'Configuration')
summary('SQLite3 Version', deps_sqlite3.version(), section: 'Configuration')
