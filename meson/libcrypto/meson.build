opt_libcrypto = get_option('signers-libcrypto')
opt_libcrypto_path = get_option('signers-libcrypto-path')
dep_libcrypto = dependency('', required: false)

ssldirs = []

if opt_libcrypto.disabled()
  if opt_libcrypto_path != ''
    warning('The signers-libcrypto option is set to `disabled` ' +
            'but a path (' + opt_libcrypto_path + ') was given ' +
            'for signers-libcrypto-path: It is going to be ignored.')
  endif

  summary('OpenSSL libcrypto', false, bool_yn: true, section: 'Crypto')
  subdir_done()
endif

# Give precedence to the custom path passed in by the user. If not, the try to find
# libcrypto using the mechanisms provided by meson (e.g. pkg-config). If that cannot be
# found, then look in some hard-coded paths below.
if opt_libcrypto_path == ''
  dep_libcrypto = dependency('libcrypto', required: false)
else
  ssldirs = [opt_libcrypto_path]
endif

if not dep_libcrypto.found()
  warning('Could not find the libcrypto dependency, going to try to find it manually')

  if ssldirs.length() == 0
    # Could not find libcrypto through pkg-config and no custom directory was passed to
    # find the library and its headers, so try to find it in some default locations.
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
    have = cxx.has_header(dir / 'include/openssl/crypto.h')
    if have
      dep_libcrypto = declare_dependency(
        link_args: ['-L' + dir / 'lib', '-lcrypto'],
        include_directories: include_directories(dir / 'include', is_system: false),
      )
      break
    endif
  endforeach
endif

if not dep_libcrypto.found()
  err_msg = 'Could not find libcrypto in ' + ', '.join(ssldirs)

  if opt_libcrypto == 'auto'
    # We could not find libcrypto anywhere, and the user did not require it.
    warning(err_msg)
    summary('OpenSSL libcrypto', false, bool_yn: true, section: 'Crypto')
    subdir_done()
  endif

  error(err_msg)
endif

if not cxx.links(fs.read('bn_new.cc'), name: 'libcrypto test program', dependencies: dep_libcrypto)
  err_msg = 'Cannot link against libcrypto'

  if opt_libcrypto == 'auto'
    # We could not link against libcrypto, and the user did not require it.
    warning(err_msg)
    summary('OpenSSL libcrypto', false, bool_yn: true, section: 'Crypto')
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
  has = cxx.has_function(func, dependencies: dep_libcrypto)
  conf.set('HAVE_' + func.to_upper(), has, description: 'Have libcrypto ' + func)
endforeach

prefix = '''
#include <stdarg.h>
#include <stddef.h>
'''
has = cxx.has_header_symbol(
  'openssl/kdf.h',
  'EVP_PKEY_CTX_set1_scrypt_salt',
  dependencies: dep_libcrypto,
  prefix: prefix,
  required: false,
)
conf.set(
  'HAVE_EVP_PKEY_CTX_SET1_SCRYPT_SALT',
  has,
  description: 'Have libcrypto EVP_PKEY_CTX_set1_scrypt_salt',
)

conf.set('HAVE_LIBCRYPTO', dep_libcrypto.found(), description: 'OpenSSL libcrypto-based signers')
summary('OpenSSL libcrypto', dep_libcrypto.found(), bool_yn: true, section: 'Crypto')

subdir('ecdsa')                 # ECDSA signers
subdir('eddsa')                 # EDDSA signers
