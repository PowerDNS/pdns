opt_lua = get_option('lua')
dep_lua = dependency('', required: false)

if opt_lua == 'auto' or opt_lua == 'luajit'
  dep_lua = dependency(
    'luajit',
    version: '>= 2.0.2',
    required: opt_lua == 'luajit',
    not_found_message: 'LuaJIT not found',
  )
endif

if not dep_lua.found() and (opt_lua == 'auto' or opt_lua == 'lua')
  variants = [
    'lua5.4',
    'lua-5.4',
    'lua54',
    'lua5.3',
    'lua-5.3',
    'lua53',
    'lua5.2',
    'lua-5.2',
    'lua52',
    'lua5.1',
    'lua-5.1',
    'lua51',
    'lua',
  ]

  foreach variant: variants
    dep_lua = dependency(variant, version: '>= 5.1', required: false)
    if dep_lua.found()
      break
    endif
  endforeach
endif

if not dep_lua.found() and opt_lua != 'lua' and opt_lua.startswith('lua')
  dep_lua = dependency(opt_lua, version: '>= 5.1', required: false)
endif

if not dep_lua.found()
  error('No Lua implementation was found')
endif

have_luahpp = cxx.has_header('lua.hpp', dependencies: dep_lua)

conf.set('HAVE_LUA', dep_lua.found(), description: 'Lua')
conf.set('HAVE_LUA_HPP', have_luahpp, description: 'Have <lua.hpp>')

if dep_lua.found() and dep_lua.name() == 'luajit'
  if target_machine.system() != 'darwin'
    # export FFI interfaces symbols, to be able to use the Lua FFI interface
    add_project_link_arguments('-Wl,--export-dynamic-symbol=dnsdist_ffi_*', language: ['c', 'cpp'])
  else
    add_project_link_arguments('-rdynamic', language: ['c', 'cpp'])
  endif
endif

summary('Lua', dep_lua.found(), bool_yn: true, section: 'Lua')
summary('Implementation', dep_lua.name(), section: 'Lua')
summary('Version', dep_lua.version(), section: 'Lua')
summary('Have <lua.hpp>', have_luahpp, bool_yn: true, section: 'Lua')
