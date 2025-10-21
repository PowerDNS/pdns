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
  result = compiler.compiles(code, name: 'uint64x2_t tests')
  assert(result, 'Compiler does not support calculation with uint64x2_t on ARM64')
endif

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
