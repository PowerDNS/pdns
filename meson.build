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

variants = [
  [
    '2-arg pthread_setname_np', 'HAVE_PTHREAD_SETNAME_NP_2', 'pthread_setname_np takes 2 arguments (Linux/glibc, QNX, IBM)',
    '''int main() { pthread_setname_np(pthread_self(), "foo"); return 0; }''',
  ],
  [
    '2-arg pthread_set_name_np', 'HAVE_PTHREAD_SET_NAME_NP_2', 'pthread_set_name_np takes 2 arguments and does not return void (FreeBSD, OpenBSD)',
    '''int main() { return pthread_set_name_np(pthread_self(), "foo"); }''',
  ],
  [
    '2-arg void pthread_set_name_np', 'HAVE_PTHREAD_SET_NAME_NP_2_VOID', 'pthread_set_name_np takes 2 arguments and returns void (FreeBSD, OpenBSD)',
    '''int main() { pthread_set_name_np(pthread_self(), "foo"); return 0; }''',
  ],
  [
    '1-arg pthread_setname_np', 'HAVE_PTHREAD_SETNAME_NP_1', 'pthread_setname_np takes 1 argument (Darwin, MacOS)',
    '''int main() { return pthread_setname_np("foo"); }''',
  ],
  [
    '3-arg pthread_setname_np', 'HAVE_PTHREAD_SETNAME_NP_3', 'pthread_setname_np takes 3 arguments (NetBSD)',
    '''int main() { return pthread_setname_np(pthread_self(), "foo", NULL); }''',
  ],
]

found_variant = false
foreach variant: variants
  variant_name = variant[0]
  variant_define = variant[1]
  variant_description = variant[2]
  variant_program = variant[3]

  if cxx.links(pthread_np_prefix + variant_program, name: variant_name)
    found_variant = true
    conf.set(variant_define, 1, description: variant_description)
    summary('pthread_setname', variant_define + ' - ' + variant_description, section: 'System')
    break
  endif
endforeach

if not found_variant
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
opt_lua = get_option('lua')
dep_lua = dependency('', required: false)

if opt_lua == 'auto' or opt_lua == 'luajit'
  dep_lua = dependency('luajit', version: '>= 2.0.2', required: opt_lua == 'luajit', not_found_message: 'LuaJIT not found')
endif

if not dep_lua.found() and (opt_lua == 'auto' or opt_lua == 'lua')
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

# Hardening ------------------------------------------------------------------------------
opt_hardening = get_option('hardening')

if opt_hardening.enabled() or opt_hardening.auto()
  hardening_features = []

  # PIE
  pie_prog = '''
    #include <pthread.h>
    __thread unsigned int t_id;

    int main() {
      t_id = 1;
      return 0;
    }
  '''

  found_variant = false
  if system == 'windows' and system == 'cygwin'
    # All code is position independent on Win32 targets.
    found_variant = true
  else
    pie_variants = [['-pie'], ['-Wl,-pie']]
    foreach variant: pie_variants
      if cxx.links(pie_prog, args: variant)
        add_global_arguments(['-fPIE'], language: ['c', 'cpp'])
        add_global_link_arguments(variant, language: ['c', 'cpp'])
        conf.set('PIE', 1, description: 'Whether we enable building a Position Independent Executable')
        found_variant = true
        break
      endif
    endforeach
  endif
  hardening_features += [[found_variant, 'Building Position Independent Executables']]
  summary('PIE', found_variant, bool_yn: true, section: 'Hardening')

  # Stack Protector
  support_stack_protector = false
  if cxx.has_argument('-fstack-protector')
    add_global_arguments(['-fstack-protector'], language: ['c', 'cpp'])
    support_stack_protector = true
  endif
  hardening_features += [[support_stack_protector, 'Stack Protector']]
  summary('Stack Protector', support_stack_protector, bool_yn: true, section: 'Hardening')

  # Stack-smashing Protection
  support_stack_smashing_protector = false
  if cxx.has_argument('--param=ssp-buffer-size=4')
    add_global_arguments(['--param=ssp-buffer-size=4'], language: ['c', 'cpp'])
    support_stack_smashing_protector = true
  endif
  hardening_features += [[support_stack_smashing_protector, 'Stack Smashing Protection']]
  summary('Stack Smashing Protection', support_stack_smashing_protector, bool_yn: true, section: 'Hardening')
  if support_stack_smashing_protector
    summary('SSP Buffer Size', 4, section: 'Hardening')
  endif

  # Fortify Source
  fortify_source_opt = get_option('fortify-source')
  if fortify_source_opt != 'disabled'
    fortify_source_level = 2
    if fortify_source_opt == 'auto'
      fortify_source_level = 3
    else
      fortify_source_level = fortify_source_opt.to_int()
    endif

    variants = [3, 2, 1]
    foreach variant: variants
      variant_str = variant.to_string()
      if fortify_source_level == variant
        if cxx.has_argument('-D_FORTIFY_SOURCE=' + variant_str)
          add_global_arguments(['-U_FORTIFY_SOURCE', '-D_FORTIFY_SOURCE=' + variant_str], language: ['c', 'cpp'])
          break
        else
          fortify_source_level = fortify_source_level - 1
        endif
      endif
    endforeach

    if fortify_source_level == 0
      fortify_source_level = 'no'
    endif
    hardening_features += [[fortify_source_level != 0, 'Source Fortification']]
    summary('Source Fortification Level', fortify_source_level, section: 'Hardening')
  endif

  # Read-only Global Offset Table
  ld_help = run_command(cxx, '-Wl,-help', '2>&1', check: true).stdout().strip()
  variants = ['relro', 'now']
  found_variant = false
  foreach variant: variants
    if ld_help.contains('-z ' + variant)
      found_variant = true
      add_global_link_arguments(['-Wl,-z', '-Wl,' + variant], language: ['c', 'cpp'])
    endif
  endforeach
  hardening_features += [[found_variant, 'Read-only Global Offset Table']]
  summary('Read-only GOT', found_variant, bool_yn: true, section: 'Hardening')

  foreach feature: hardening_features
    available = feature[0]
    name = feature[1]
    if not available
      if opt_hardening.auto()
        warning(name + ' is not supported')
      else
        error('Failing because ' + name + ' is not supported but hardening was explicitly requested.')
      endif
    endif
  endforeach
endif

# Unsafe KISS RNG ------------------------------------------------------------------------
opt_kiss_rng = get_option('kiss-rng')
if opt_kiss_rng
  conf.set('HAVE_KISS_RNG', 1, 'Use the unsafe KISS RNG')
endif
summary('Unsafe KISS RNG', opt_kiss_rng, section: 'Configuration')

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
