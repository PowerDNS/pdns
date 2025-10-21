opt_ipcrypt2 = get_option('ipcrypt2')

can_build=true
if target_machine.cpu_family() == 'aarch64'
  code = '''
#    if defined(_MSC_VER) && defined(_M_ARM64)
#        include <arm64_neon.h>
#    else
#        include <arm_neon.h>
#    endif
int main() {
  uint64x2_t foo = {0, 0};
  uint64x2_t bar = vshrq_n_u8(foo, 1);
  return 0;
}
'''
  compiler = meson.get_compiler('cpp')
  can_build = compiler.compiles(code, name: 'uint64x2_t tests')
endif


dep_ipcrypt2 = declare_dependency()

if can_build
lib_ipcrypt2 = static_library(
  'ipcrypt2',
  'ipcrypt2.c',
  extra_files: [
    'include/ipcrypt2.h',
    'LICENSE',
    'README.md',
  ],
)

dep_ipcrypt2 = declare_dependency(
  link_with: lib_ipcrypt2,
  include_directories: include_directories('./include'),
)
endif

if not can_build and opt_ipcrypt2.enabled()
  error('ipcrypt2 support was requested but ipcrypt2 can not be built')
endif
enable_ipcrypt2 = can_build and not opt_ipcrypt2.disabled()
conf.set('HAVE_IPCRYPT2', enable_ipcrypt2, description: 'ipcrypt2 support')
summary('ipcrypt2', enable_ipcrypt2, bool_yn: true, section: 'Configuration')
