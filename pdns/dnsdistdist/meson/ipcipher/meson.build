opt_ipcipher = get_option('ipcipher')

if not dep_libcrypto.found() and opt_ipcipher.enabled()
  error('ipcipher support was requested but libcrypto is not available')
endif

enable_ipcipher = dep_libcrypto.found() and not opt_ipcipher.disabled()
conf.set('HAVE_IPCIPHER', enable_ipcipher, description: 'ipcipher support')
summary('ipcipher', enable_ipcipher, bool_yn: true, section: 'Configuration')
