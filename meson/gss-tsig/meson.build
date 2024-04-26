opt = get_option('experimental-gss-tsig')

dep_krb5 = dependency('krb5', required: opt)
dep_krb5_gssapi = dependency('krb5-gssapi', required: opt)

found = dep_krb5.found() and dep_krb5_gssapi.found()
conf.set('ENABLE_GSS_TSIG', found, description: 'GSS-TSIG')

summary('GSS-TSIG', found, bool_yn: true, section: 'GSS-TSIG')
summary('Krb5', dep_krb5.version(), section: 'GSS-TSIG')
summary('Krb5 GSSAPI', dep_krb5_gssapi.version(), section: 'GSS-TSIG')

dep_gss_tsig = dependency('', required: false)
if found
  dep_gss_tsig = declare_dependency(
    dependencies: [
      dep_krb5,
      dep_krb5_gssapi,
    ]
  )
endif
