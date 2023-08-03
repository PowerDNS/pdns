# OpenSSL-based signers
# Inputs: deps conf
# Outputs: have_libcrypto dep_libcrypto

opt_libcrypto = get_option('libcrypto')
dep_libcrypto = dependency('', required: false)

ssldirs = []
have_libcrypto = false
if opt_libcrypto == ''
  error('Invalid value for libcrypto option, either use auto, yes, no, ' +
        'or pass a directory where the library can be found')
endif

if opt_libcrypto == 'no'
  subdir_done()
endif

# Generally, try to find libcrypto using the mechanisms provided by meson
# (e.g. pkg-config). If an explicit directory for libcrypto was passed, use that instead.
if opt_libcrypto == 'auto' or opt_libcrypto == 'yes'
  dep_libcrypto = dependency('libcrypto', required: false)
  have_libcrypto = dep_libcrypto.found()
else
  ssldirs = [opt_libcrypto]
endif

libdir = ''
if not have_libcrypto
  warning('Could not find the libcrypto dependency, going to try to find it manually')

  # Could not find libcrypto through e.g. pkg-config, and no explicit directory was passed
  # to find the library and its headers, so try to find it in some default locations.
  if ssldirs.length() == 0
    ssldirs = [
      '/usr/local/ssl',
      '/usr/lib/ssl',
      '/usr/ssl',
      '/usr/pkg',
      '/usr/local',
      '/usr'
    ]
  endif

  foreach dir: ssldirs
    have_libcrypto = cxx.has_header(dir / 'include/openssl/crypto.h')
    if have_libcrypto
      libdir = dir
      break
    endif
  endforeach
endif

if not have_libcrypto
  dirs_str = ', '.join(ssldirs)
  err_msg = 'Could not find libcrypto in ' + dirs_str

  # It's fine if we couldn't find libcrypto anywhere, the user didn't require it anyway.
  if opt_libcrypto == 'auto'
    warning(err_msg)
    subdir_done()
  endif

  error(err_msg)
endif

# Now, either we have a meson dependency object because we could detect libcrypto through
# e.g. pkg-config, or we found it manually either through a user-provided directory or by
# finding it in some default locations (see the list of hard-coded directories above).
#
# In the first case, we use the existing dep_libcrypto object as a dependency and keep the
# _args and _incs lists empty. In the latter cases we do the opposite (we expect the
# dep_libcrypto object to be empty anyway).

libcrypto_args = []             # Compiler arguments
libcrypto_incs = []             # Include directories
if libdir != ''
  libcrypto_args = ['-L' + libdir / 'lib', '-lcrypto']
  libcrypto_incs = include_directories(libdir / 'include', is_system: false)
endif

prog = '''
#include <openssl/bn.h>

int main() {
  BN_new();
  return 0;
}
'''
if not cxx.links(prog, name: 'libcrypto test program', args: libcrypto_args, include_directories: libcrypto_incs, dependencies: dep_libcrypto)
  err_msg = 'Cannot link against libcrypto'

  # It's fine if we couldn't link against libcrypto, the user didn't require it anyway.
  if opt_libcrypto == 'auto'
    warning(err_msg)
    subdir_done()
  endif

  error(err_msg)
endif

funcs = [
  'RAND_bytes',
  'RAND_pseudo_bytes',
  'CRYPTO_memcmp',
  'OPENSSL_init_crypto',
  'EVP_MD_CTX_new',
  'EVP_MD_CTX_free',
  'RSA_get0_key',
  'OCSP_basic_sign',
]
foreach func: funcs
  has = cxx.has_function(func, args: libcrypto_args, include_directories: libcrypto_incs, dependencies: dep_libcrypto)
  conf.set10('HAVE_' + func.to_upper(), has, description: 'Whether we have ' + func)
endforeach

prefix = '''
#include <stdarg.h>
#include <stddef.h>
'''
has = cxx.has_header_symbol('openssl/kdf.h', 'EVP_PKEY_CTX_set1_scrypt_salt', args: libcrypto_args, include_directories: libcrypto_incs, dependencies: dep_libcrypto, prefix: prefix, required: true)
conf.set10('HAVE_EVP_PKEY_CTX_SET1_SCRYPT_SALT', has, description: 'Whether we have EVP_PKEY_CTX_set1_scrypt_salt')

if libdir != ''
  add_global_arguments(libcrypto_args + ['-I' + libdir / 'include'])
else
  deps += dep_libcrypto
endif

conf.set10('HAVE_LIBCRYPTO', have_libcrypto, description: 'Whether we build OpenSSL libcrypto-based signers')
summary('OpenSSL libcrypto', have_libcrypto, bool_yn: true, section: 'Configuration')

subdir('ecdsa')                 # ECDSA signers
subdir('eddsa')                 # EDDSA signers
