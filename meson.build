project(
  'pdns',
  ['c', 'cpp'],
  # version: 4.7.0, # Rework this since it should call builder-support/gen-version
  # license_files: 'LICENSE', # Meson 1.1.0
  meson_version: '>= 0.53',
  default_options: [
    'buildtype=debugoptimized',
    'warning_level=2', # Move this to 3 at some point to enable -Wpedantic
    'cpp_std=c++17',
  ],
)

# Don't limit the number of errors when using clang. This is useful to not cut out the
# error output when using an LSP server like clangd.
if meson.get_compiler('cpp').get_id() == 'clang'
  add_global_arguments(['-ferror-limit=0'], language: ['c', 'cpp'])
endif

add_global_arguments(['-Wshadow', '-Wmissing-declarations', '-Wredundant-decls'], language: ['c', 'cpp'])

summary('Source Dir', meson.current_source_dir(), section: 'Build')
summary('Build Dir', meson.current_build_dir(), section: 'Build')

cxx = meson.get_compiler('cpp')
system = target_machine.system()

summary('System', system, section: 'System')
summary('C++ Compiler', cxx.get_id(), section: 'System')
summary('C++ Compiler Version', cxx.version(), section: 'System')
summary('C++ Compiler Command', cxx.cmd_array(), section: 'System')
summary('Linker', cxx.get_linker_id(), section: 'System')

summary('Name', meson.project_name(), section: 'PowerDNS')
summary('Version', meson.project_version(), section: 'PowerDNS')
# summary('Source Root', meson.project_source_root(), section: 'PowerDNS') # Meson 0.56
# summary('Build Root', meson.project_build_root(), section: 'PowerDNS') # Meson 0.56

# Create the configuration data object.
conf = configuration_data()

# Figure out the size of time_t ----------------------------------------------------------
timet_size = cxx.sizeof('time_t', prefix: '#include <sys/types.h>')
if timet_size < 8
  error('size of time_t is', timet_size, 'which is not large enough to fix the y2k38 bug')
endif

summary('Size of time_t', timet_size, section: 'System')

# Figure out the sign of time_t ----------------------------------------------------------
prog = '''
#include <sys/types.h>

int main() {
  int foo[1 - 2 * !(((time_t) -1) < 0)];
  (void)foo[0];
  return 0;
}
'''
if cxx.compiles(prog, name: 'time_t is signed') == false
  error('time_t is unsigned, PowerDNS code relies on it being signed')
endif

summary('Signed time_t', true, section: 'System', bool_yn: true)

# Find flex and bison --------------------------------------------------------------------
flex = find_program('flex', required: true)
# summary('Flex', flex.full_path(), section: 'System') # Meson 0.55
# summary('Flex Version', flex.version(), section: 'System') # Meson 0.62

bison = find_program('bison', required: true)
# summary('Bison', bison.full_path(), section: 'System') # Meson 0.55
# summary('Bison Version', bison.version(), section: 'System') # Meson 0.62

# Platform stuff -------------------------------------------------------------------------
if system == 'sunos'
  conf.set('NEED_POSIX_TYPEDEF', 1, description: 'POSIX typedefs need to be defined')
  conf.set('NEED_INET_NTOP_PROTO', 1, description: 'OS is so broken that it needs an additional prototype')
  deps += cxx.find_library('posix4', required: true)
  add_project_arguments(['-D_REENTRANT'], language: 'cpp')
  conf.set('HAVE_SOLARIS', 1, description: 'We are on Solaris/SunOS')
  summary('SunOS defines', 'NEED_POSIX_TYPEDEF NEED_INET_NTOP_PROTO HAVE_SOLARIS _REENTRANT', section: 'System')
elif system == 'linux'
  conf.set('HAVE_LINUX', 1, description: 'We are on Linux')
  summary('Linux defines', 'HAVE_LINUX', section: 'System')
elif system == 'darwin'
  add_project_arguments(['-D__APPLE_USE_RFC_3542', '-D_XOPEN_SOURCE', '-D_DARWIN_C_SOURCE'], language: 'cpp')
  conf.set('HAVE_DARWIN', 1, description: 'We are on Darwin/MacOS')
  summary('Darwin/MacOS defines', '__APPLE_USE_RFC_3542 _XOPEN_SOURCE _DARWIN_C_SOURCE', section: 'System')
elif system == 'freebsd'
  conf.set('HAVE_FREEBSD', 1, description: 'We are on FreeBSD')
  summary('FreeBSD defines', 'HAVE_FREEBSD', section: 'System')
elif system == 'openbsd'
  conf.set('HAVE_OPENBSD', 1, description: 'We are on OpenBSD')
  summary('OpenBSD defines', 'HAVE_OPENBSD', section: 'System')
endif

# Atomics --------------------------------------------------------------------------------
dep_atomics = []
atomic_builtins_prog = '''
#include <stdint.h>

int main() {
  uint64_t val = 0;
  __atomic_add_fetch(&val, 1, __ATOMIC_RELAXED);
  return 0;
}
'''
need_latomic = false
if cxx.links(atomic_builtins_prog, name: '-latomic is not needed for using __atomic builtins') == false
  atomic = cxx.find_library('atomic', disabler: true, required: false)
  if atomic.found()
    if cxx.links(atomic_builtins_prog, name: '-latomic is needed for using __atomic builtins', dependencies: atomic)
      need_latomic = true
      summary('Atomics Library', atomic, section: 'System')
      dep_atomics += atomic
    else
      error('libatomic needed but could not be found')
    endif
  else
    error('libatomic needed and was found, but linking with it failed')
  endif
endif

summary('Need -latomic', need_latomic, section: 'System')

# Threads --------------------------------------------------------------------------------
dep_threads = dependency('threads')
summary('Threads', dep_threads.name(), section: 'System')

cxx.check_header('pthread.h', dependencies: dep_threads, required: true)
if cxx.check_header('pthread_np.h', dependencies: dep_threads, prefix: '#include <pthread.h>')
  conf.set('HAVE_PTHREAD_NP_H', 1, description: 'pthread_np.h is available')
else
  summary('Have pthread_np.h', false, section: 'System')
endif

# pthread_setname_np madness -------------------------------------------------------------
pthread_np_prefix = '''
#include <pthread.h>
#if HAVE_PTHREAD_NP_H
#  include <pthread_np.h>
#endif
'''

if cxx.links(pthread_np_prefix + '''
             int main() {
                 pthread_setname_np(pthread_self(), "foo");
                 return 0;
             }
             ''',
             name: 'for 2-arg pthread_setname_np')
  conf.set('HAVE_PTHREAD_SETNAME_NP_2', 1, description: 'pthread_setname_np takes 2 arguments (Linux/glibc, QNX, IBM)')
elif cxx.links(pthread_np_prefix + '''
               int main() {
                   return pthread_set_name_np(pthread_self(), "foo");
               }
               ''',
               name: '2-arg pthread_set_name_np')
  conf.set('HAVE_PTHREAD_SET_NAME_NP_2', 1, description: 'pthread_set_name_np takes 2 arguments and does not return void (FreeBSD, OpenBSD)')
elif cxx.links(pthread_np_prefix + '''
               int main() {
                   pthread_set_name_np(pthread_self(), "foo");
                   return 0;
               }
               ''',
               name: '2-arg void pthread_set_name_np')
  conf.set('HAVE_PTHREAD_SET_NAME_NP_2_VOID', 1, description: 'pthread_set_name_np takes 2 arguments and returns void (FreeBSD, OpenBSD)')
elif cxx.links(pthread_np_prefix + '''
               int main() {
                   return pthread_setname_np("foo");
               }
               ''',
               name: '1-arg pthread_setname_np')
  conf.set('HAVE_PTHREAD_SETNAME_NP_1', 1, description: 'pthread_setname_np takes 1 argument (Darwin, MacOS)')
elif cxx.links(pthread_np_prefix + '''
               int main() {
                   return pthread_setname_np(pthread_self(), "foo", NULL);
               }
               ''',
               name: '3-arg pthread_setname_np')
  conf.set('HAVE_PTHREAD_SETNAME_NP_3', 1, description: 'pthread_setname_np takes 3 arguments (NetBSD)')
else
  error('Could not find a suitable pthread_setname function')
endif

# strerror_r -----------------------------------------------------------------------------
if cxx.has_header_symbol('string.h', 'strerror_r') == true
  conf.set('HAVE_DECL_STRERROR_R', 1, description: 'Whether strerror_r is declared')
endif

have_strerror_r = false
strerror_r_returns_charp = false

if cxx.has_function('strerror_r', prefix: '#include <string.h>') == true
  have_strerror_r = true
  conf.set('HAVE_STRERROR_R', 1, description: 'Whether strerror_r is available')

  if cxx.compiles('''
                  #include <string.h>
                  int main () {
                      char error_string[256];
                      char *ptr = strerror_r(-2, error_string, 256);
                      char c = *strerror_r(-2, error_string, 256);
                      return c != 0 && ptr != (void*) 0L;
                  }
                  ''',
                  name: 'strerror_r() returns char *')
    strerror_r_returns_charp = true
    conf.set('STRERROR_R_CHAR_P', 1, description: 'Whether strerror_r returns char *')
  endif
endif

summary('Have strerror_r', have_strerror_r, section: 'System')
summary('strerror_r returns char *', strerror_r_returns_charp, section: 'System')

# Lua ------------------------------------------------------------------------------------
lua_opt = get_option('lua')
dep_lua = dependency('', required: false)

if lua_opt == 'auto' or lua_opt == 'luajit'
  dep_lua = dependency('luajit', version: '>= 2.0.2', required: lua_opt == 'luajit', not_found_message: 'LuaJIT not found')
endif

if not dep_lua.found() and (lua_opt == 'auto' or lua_opt == 'lua')
  variants = ['lua5.3', 'lua-5.3', 'lua53', 'lua5.2', 'lua-5.2', 'lua52', 'lua5.1', 'lua-5.1', 'lua51', 'lua']
  foreach variant: variants
    dep_lua = dependency(variant, version: '>= 5.1', required: false)
    if dep_lua.found()
      break
    endif
  endforeach
endif

if not dep_lua.found()
  error('No Lua implementation was found')
endif

conf.set('HAVE_LUA', 1, description: 'Whether we have Lua')
summary('Lua implementation', dep_lua.name(), section: 'Configuration')

have_luahpp = false
if cxx.has_header('lua.hpp', dependencies: dep_lua)
  have_luahpp = true
  conf.set('HAVE_LUA_HPP', 1, description: 'Whether we have lua.hpp')
endif

summary('Have lua.hpp', have_luahpp, bool_yn: true, section: 'Configuration')
# Generate config.h ----------------------------------------------------------------------
config_h = configure_file(configuration: conf, output: 'config.h')
# summary('Defines', conf.keys(), section: 'Build Configuration') # Meson 0.57

# Create the dependencies list -----------------------------------------------------------
deps = []
deps += dep_atomics
deps += dep_threads
deps += dep_lua

# TODO: Other source files
auth = executable('pdns', config_h, dependencies: deps, export_dynamic: true)

# # Generate bindlexer.c and bindparser.cc.
# bindlexer_c = generator(flex,
# bindparser_cc = generator(bison,
