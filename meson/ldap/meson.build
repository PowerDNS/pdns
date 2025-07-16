dep_ldap = dependency('', required: false)

if get_option('module-ldap') != 'disabled'
  dep_ldap_internal = dependency('ldap', required: false)
  dep_lber_internal = dependency('lber', required: false)
  dep_krb5_internal = dependency('krb5', required: true)

  if not dep_ldap_internal.found()
    lib_ldap_internal = cxx.find_library('ldap', disabler: true, required: true)
    dep_ldap_internal = declare_dependency(dependencies: lib_ldap_internal)
  endif
  if not dep_lber_internal.found()
    lib_lber_internal = cxx.find_library('lber', disabler: true, required: true)
    dep_lber_internal = declare_dependency(dependencies: lib_lber_internal)
  endif

  conf.set('HAVE_LIBLDAP', dep_ldap_internal.found(), description: 'Have libldap')

  have_ldap_initialize = cxx.has_function('ldap_initialize', dependencies: dep_ldap_internal)
  conf.set(
    'HAVE_LDAP_INITIALIZE',
    have_ldap_initialize,
    description: 'Have ldap_initialize',
  )

  have_ldap_sasl_bind = cxx.has_function('ldap_sasl_bind', dependencies: dep_ldap_internal)
  conf.set(
    'HAVE_LDAP_SASL_BIND',
    have_ldap_initialize,
    description: 'Have ldap_sasl_bind',
  )

  have_krb5_get_init_creds_opt_set_default_flags = cxx.has_function(
    'krb5_get_init_creds_opt_set_default_flags',
    dependencies: dep_krb5_internal,
  )
  conf.set(
    'HAVE_KRB5_GET_INIT_CREDS_OPT_SET_DEFAULT_FLAGS',
    have_krb5_get_init_creds_opt_set_default_flags,
    description: 'Have krb5_get_init_creds_opt_set_default_flags',
  )

  dep_ldap = declare_dependency(
    dependencies: [
      dep_ldap_internal,
      dep_lber_internal,
      dep_krb5_internal,
    ],
  )

  summary('LDAP', dep_ldap_internal.found(), bool_yn: true, section: 'LDAP')
  if dep_ldap_internal.found()
    summary('LDAP Name', dep_ldap_internal.name(), section: 'LDAP')
    summary('LDAP Version', dep_ldap_internal.version(), section: 'LDAP')
  endif

  summary('LBER', dep_lber_internal.found(), bool_yn: true, section: 'LDAP')
  if dep_lber_internal.found()
    summary('LBER Name', dep_lber_internal.name(), section: 'LDAP')
    summary('LBER Version', dep_lber_internal.version(), section: 'LDAP')
  endif

  summary('Krb5', dep_krb5_internal.found(), bool_yn: true, section: 'LDAP')
  if dep_krb5_internal.found()
    summary('Krb5 Name', dep_krb5_internal.name(), section: 'LDAP')
    summary('Krb5 Version', dep_krb5_internal.version(), section: 'LDAP')
  endif
endif
