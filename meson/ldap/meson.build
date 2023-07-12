# LDAP
# Outputs: deps_ldap

deps_ldap  = [dependency('ldap', required: true)]
deps_ldap += dependency('lber', required: true)
deps_ldap += dependency('krb5', required: true)

conf.set10('LDAP', true, description: 'Enable LDAP')
summary('LDAP', 'With libldap ' + deps_ldap[0].version() + ', liblber ' + deps_ldap[1].version() + ' and krb5 ' + deps_ldap[2].version(), bool_yn: true, section: 'Configuration')
