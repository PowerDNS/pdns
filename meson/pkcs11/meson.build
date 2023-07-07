# PKCS11
# Inputs: conf deps

prog = '''
#include <p11-kit/p11-kit.h>

int main() {
    void *foo = p11_kit_module_for_name(0, 0);
    return 0;
}
'''

opt_pkcs11 = get_option('pkcs11')
conf.set10('PKCS11', opt_pkcs11, description: 'Whether to enable PKCS11 support (experimental)')

if opt_pkcs11
  dep_pkcs11 = dependency('p11-kit-1', required: opt_pkcs11)
  conf.set10('HAVE_P11KIT1', dep_pkcs11.found(), description: 'Whether we have p11-kit-1')

  has = cxx.links(prog, dependencies: dep_pkcs11, name: 'we can link to p11kit1')
  conf.set10('HAVE_P11KIT1_V2', has, description: 'Whether we have p11-kit-1 0.20 or newer')

  if not has
    warning('Could not find p11-kit-1')
  endif

  deps += dep_pkcs11
endif
