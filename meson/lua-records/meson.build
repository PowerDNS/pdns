# Lua Records
# Inputs: conf deps opt_lua dep_lua

opt_lua_records = get_option('lua-records')

dep_libcurl = dependency('libcurl', version: '>= 7.21.3', required: opt_lua_records)
deps += dep_libcurl
conf.set10('HAVE_LIBCURL', dep_libcurl.found(), description: 'Whether we have libcurl')

opt_lua_enabled = opt_lua in ['auto', 'luajit', 'lua']

if not opt_lua_enabled
  error('Lua records require Lua, make sure it is enabled')
endif

if not dep_lua.found()
  error('Lua records require Lua, make sure it is detected on your system')
endif

found = opt_lua_records and opt_lua_enabled and dep_lua.found() and dep_libcurl.found()
conf.set('HAVE_LUA_RECORDS', found, description: 'Whether we have Lua records')
summary('Lua Records', found, bool_yn: true, section: 'Configuration')
