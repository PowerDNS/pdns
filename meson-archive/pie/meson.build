# PIE
# Inputs: hardening_features conf

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

    if cxx.links(prog, args: cflags + ldflags, name: 'compiler can build Position Independent Executables')
      add_global_arguments(cflags, language: ['cpp'])
      add_global_link_arguments(ldflags, language: ['cpp'])
      found_variant = true
      break
    endif
  endforeach
endif

hardening_features += [[found_variant, 'Building position independent executables (PIEs)']]
conf.set10('PIE', found_variant, description: 'Whether we enable building a Position Independent Executable (PIE)')
summary('PIE', found_variant, bool_yn: true, section: 'Hardening')
