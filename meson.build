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

cxx = meson.get_compiler('cpp')

# Create the configuration data object.
conf = configuration_data()

# Figure out the size of time_t ----------------------------------------------------------
timet_size = cxx.sizeof('time_t', prefix: '#include <sys/types.h>')
if timet_size < 8
  error('size of time_t is', timet_size, 'which is not large enough to fix the y2k38 bug')
endif

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

# Find flex and bison --------------------------------------------------------------------
flex = find_program('flex', required: true)
bison = find_program('bison', required: true)

# Platform stuff -------------------------------------------------------------------------
system = target_machine.system()
if system == 'sunos'
  conf.set('NEED_POSIX_TYPEDEF', 1, description: 'POSIX typedefs need to be defined')
  conf.set('NEED_INET_NTOP_PROTO', 1, description: 'OS is so broken that it needs an additional prototype')
  deps += cxx.find_library('posix4', required: true)
  add_project_arguments(['-D_REENTRANT'], language: 'cpp')
  conf.set('HAVE_SOLARIS', 1, description: 'We are on Solaris/SunOS')
elif system == 'linux'
  conf.set('HAVE_LINUX', 1, description: 'We are on Linux')
elif system == 'darwin'
  add_project_arguments(['-D__APPLE_USE_RFC_3542', '-D_XOPEN_SOURCE', '-D_DARWIN_C_SOURCE'], language: 'cpp')
  conf.set('HAVE_DARWIN', 1, description: 'We are on Darwin/MacOS')
elif system == 'freebsd'
  conf.set('HAVE_FREEBSD', 1, description: 'We are on FreeBSD')
elif system == 'openbsd'
  conf.set('HAVE_OPENBSD', 1, description: 'We are on OpenBSD')
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
if cxx.links(atomic_builtins_prog, name: 'whether -latomic is not needed for using __atomic builtins') == false
  atomic = cxx.find_library('atomic', disabler: true, required: false)
  if atomic.found()
    if cxx.links(atomic_builtins_prog, name: 'whether -latomic is needed for using __atomic builtins', dependencies: atomic)
      dep_atomics += atomic
    else
      error('libatomic needed but could not be found')
    endif
  else
    error('libatomic needed and was found, but linking with it failed')
  endif
endif

# Threads --------------------------------------------------------------------------------
dep_threads = dependency('threads')

cxx.check_header('pthread.h', dependencies: dep_threads, required: true)
if cxx.check_header('pthread_np.h', dependencies: dep_threads, prefix: '#include <pthread.h>')
  conf.set('HAVE_PTHREAD_NP_H', 1, description: 'pthread_np.h is available')
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

if cxx.has_function('strerror_r', prefix: '#include <string.h>') == true
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
    conf.set('STRERROR_R_CHAR_P', 1, description: 'Whether strerror_r returns char *')
  endif
endif

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

if cxx.has_header('lua.hpp', dependencies: dep_lua)
  conf.set('HAVE_LUA_HPP', 1, description: 'Whether we have lua.hpp')
endif

# Generate config.h ----------------------------------------------------------------------
config_h = configure_file(configuration: conf, output: 'config.h')

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
