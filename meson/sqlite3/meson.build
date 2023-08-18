dep_sqlite3 = dependency('sqlite3', required: true)

conf.set('HAVE_SQLITE3', dep_sqlite3.found(), description: 'Sqlite3')
conf.set('SQLITE3', dep_sqlite3.found(), description: 'Sqlite3')

summary('SQLite3', dep_sqlite3.found(), bool_yn: true, section: 'SQLite3')

if dep_sqlite3.found()
  summary('Version', dep_sqlite3.version(), section: 'SQLite3')
endif
