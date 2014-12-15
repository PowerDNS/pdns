AC_DEFUN([PDNS_CHECK_LDAP],[
  AC_CHECK_HEADERS([ldap.h],
    [],
    [AC_MSG_ERROR([ldap header (ldap.h) not found])]
  )

  AC_CHECK_HEADERS([lber.h],
    [],
    [AC_MSG_ERROR([ldap header (lber.h) not found])]
  )

  AC_CHECK_LIB([ldap_r], [ldap_set_option],
    [
      AC_DEFINE([HAVE_LIBLDAP_R], [1], [Have -lldap_r])
      LIBLDAP="ldap_r"
      LDAP_LIBS="-lldap_r -llber"
    ],
    [
      AC_CHECK_LIB([ldap], [ldap_set_option],
        [
          AC_DEFINE([HAVE_LIBLDAP], 1, [Have -lldap])
          LIBLDAP="ldap"
          LDAP_LIBS="-lldap -llber"
        ],
        [AC_MSG_ERROR([ldap library (libldap) not found])]
      )
    ]
  )

  AC_CHECK_LIB([$LIBLDAP], [ldap_initialize],
    [AC_DEFINE([HAVE_LDAP_INITIALIZE], 1, [Define to 1 if you have ldap_initialize])]
  )

  AC_CHECK_LIB([$LIBLDAP], [ldap_sasl_bind],
    [AC_DEFINE([HAVE_LDAP_SASL_BIND], 1, [Define to 1 if you have ldap_sasl_bind])]
  )

  AC_ARG_VAR([LDAP_LIBS], [linker flags for openldap])
])
