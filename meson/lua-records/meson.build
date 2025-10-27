opt_lua_records = get_option('lua-records')

dep_libcurl = dependency('libcurl', version: '>= 7.21.3', required: opt_lua_records)
conf.set('HAVE_LIBCURL', dep_libcurl.found(), description: 'Whether we have libcurl')

opt_lua_enabled = opt_lua in ['auto', 'luajit', 'lua', 'lua51', 'lua-5.1', 'lua5.1', 'lua52', 'lua-5.2', 'lua5.2', 'lua53', 'lua-5.3', 'lua5.3', 'lua54', 'lua-5.4', 'lua5.4']

if not opt_lua_enabled
  error('Lua records require Lua, make sure it is enabled')
endif

if not dep_lua.found()
  error('Lua records require Lua, make sure it is detected on your system')
endif

have_lua_records = opt_lua_records and \
                   opt_lua_enabled and \
                   dep_lua.found() and \
                   dep_libcurl.found()

dep_lua_records = dependency('', required: false)
if have_lua_records
  dep_lua_records = declare_dependency(
    dependencies: [
      dep_lua,
      dep_libcurl,
    ],
  )
endif

conf.set('HAVE_LUA_RECORDS', have_lua_records, description: 'Lua-based records')
summary('Lua-based Records', have_lua_records, bool_yn: true, section: 'Configuration')
