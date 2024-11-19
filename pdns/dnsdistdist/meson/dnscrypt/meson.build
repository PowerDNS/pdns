opt_dnscrypt = get_option('dnscrypt')

if opt_dnscrypt.enabled() and not dep_libsodium.found()
  error('DNSCrypt support requested but libsodium is not available')
endif

conf.set('HAVE_DNSCRYPT', opt_dnscrypt.allowed() and dep_libsodium.found(), description: 'DNSCrypt support')
summary('DNSCrypt support', opt_dnscrypt.allowed() and dep_libsodium.found(), bool_yn: true, section: 'Crypto')
