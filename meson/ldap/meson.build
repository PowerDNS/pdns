dep_ldap = dependency('ldap', required: true)
dep_lber = dependency('lber', required: true)
dep_krb5 = dependency('krb5', required: true)

conf.set('LDAP', dep_ldap.found(), description: 'LDAP')

summary('LDAP', dep_ldap.found(), bool_yn: true, section: 'LDAP')
summary('LDAP Name', dep_ldap.name(), section: 'LDAP')
summary('LDAP Version', dep_ldap.version(), section: 'LDAP')

summary('LBER', dep_lber.found(), bool_yn: true, section: 'LDAP')
summary('LBER Name', dep_lber.name(), section: 'LDAP')
summary('LBER Version', dep_lber.version(), section: 'LDAP')

summary('Krb5', dep_krb5.found(), bool_yn: true, section: 'LDAP')
summary('Krb5 Name', dep_krb5.name(), section: 'LDAP')
summary('Krb5 Version', dep_krb5.version(), section: 'LDAP')

dep_ldap = declare_dependency(
  dependencies: [
    dep_ldap,
    dep_lber,
    dep_krb5,
  ],
)
