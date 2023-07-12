# PIE
# Inputs: hardening_features conf deps

prog = '''
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
  pie_variants = [
    [['-fPIE', '-DPIE'], ['-pie']],
    [['-fPIE', '-DPIE'], ['-Wl,-pie']],
  ]
  foreach variant: pie_variants
    cflags = variant[0]
    ldflags = variant[1]
    dep_pie = declare_dependency(compile_args: cflags, link_args: ldflags)

    # if cxx.links(prog, dependencies: dep_pie, name: 'compiler can build Position Independent Executables')   # TODO Meson 0.57
    if cxx.links(prog, args: cflags + ldflags, name: 'compiler can build Position Independent Executables')
      deps += dep_pie
      found_variant = true
      break
    endif
  endforeach
endif

hardening_features += [[found_variant, 'Building position independent executables (PIEs)']]
conf.set10('PIE', found_variant, description: 'Whether we enable building a Position Independent Executable (PIE)')
summary('PIE', found_variant, bool_yn: true, section: 'Hardening')
