# GSS-TSIG
# Inputs: conf deps

opt_gss_tsig = get_option('gss-tsig')
conf.set10('GSS_TSIG', opt_gss_tsig, description: 'Whether to enable GSS-TSIG support')

dep_krb5 = dependency('krb5', required: opt_gss_tsig)
dep_krb5_gssapi = dependency('krb5-gssapi', required: opt_gss_tsig)
conf.set10('ENABLE_GSS_TSIG', dep_krb5.found() and dep_krb5_gssapi.found(), description: 'Whether we have GSS-TSIG support')

deps += dep_krb5
deps += dep_krb5_gssapi

value = dep_krb5.found() and dep_krb5_gssapi.found() ? 'With krb5 ' + dep_krb5.version() + ' and krb5-gssapi ' + dep_krb5_gssapi.version() : false
summary('GSS-TSIG', value, bool_yn: opt_gss_tsig, section: 'Configuration')
