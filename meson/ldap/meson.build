dep_ldap = dependency('ldap', required: true)
dep_lber = dependency('lber', required: true)
dep_krb5 = dependency('krb5', required: true)

conf.set('HAVE_LIBLDAP', dep_ldap.found(), description: 'Have libldap')

have_ldap_initialize = cxx.has_function('ldap_initialize', dependencies: dep_ldap)
conf.set(
  'HAVE_LDAP_INITIALIZE',
  have_ldap_initialize,
  description: 'Have ldap_initialize',
)

have_ldap_sasl_bind = cxx.has_function('ldap_sasl_bind', dependencies: dep_ldap)
conf.set(
  'HAVE_LDAP_SASL_BIND',
  have_ldap_initialize,
  description: 'Have ldap_sasl_bind',
)

summary('LDAP', dep_ldap.found(), bool_yn: true, section: 'LDAP')
summary('LDAP Name', dep_ldap.name(), section: 'LDAP')
summary('LDAP Version', dep_ldap.version(), section: 'LDAP')

summary('LBER', dep_lber.found(), bool_yn: true, section: 'LDAP')
summary('LBER Name', dep_lber.name(), section: 'LDAP')
summary('LBER Version', dep_lber.version(), section: 'LDAP')

summary('Krb5', dep_krb5.found(), bool_yn: true, section: 'LDAP')
summary('Krb5 Name', dep_krb5.name(), section: 'LDAP')
summary('Krb5 Version', dep_krb5.version(), section: 'LDAP')

have_krb5_get_init_creds_opt_set_default_flags = \
  cxx.has_function(
    'krb5_get_init_creds_opt_set_default_flags',
    dependencies: dep_krb5,
  )
conf.set(
  'HAVE_KRB5_GET_INIT_CREDS_OPT_SET_DEFAULT_FLAGS',
  have_krb5_get_init_creds_opt_set_default_flags,
  description: 'Have krb5_get_init_creds_opt_set_default_flags',
)

dep_ldap = declare_dependency(
  dependencies: [
    dep_ldap,
    dep_lber,
    dep_krb5,
  ],
)
