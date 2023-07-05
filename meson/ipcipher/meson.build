# IPCipher
# Inputs: conf have_libcrypto

opt_ipcipher = get_option('ipcipher')

if not have_libcrypto and opt_ipcipher.enabled()
  error('ipcipher support was requested but libcrypto is not available')
endif

enable_ipcipher = have_libcrypto and not opt_ipcipher.disabled()
conf.set10('HAVE_IPCIPHER', enable_ipcipher, description: 'Whether ipcipher support is enabled')
show_colors = have_libcrypto or not opt_ipcipher.auto()
summary('ipcipher', enable_ipcipher, bool_yn: show_colors, section: 'Configuration')
