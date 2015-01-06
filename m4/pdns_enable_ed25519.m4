AC_DEFUN([PDNS_ENABLE_ED25519], [
  AC_MSG_CHECKING([whether we will be linking in Ed25519])
  AC_ARG_ENABLE([experimental-ed25519],
    AS_HELP_STRING([--enable-experimental-ed25519],
      [use experimental Ed25519 @<:@default=no@:>@]),
    [enable_ed25519=$enableval],
    [enable_ed25519=no]
  )
  AC_MSG_RESULT([$enable_ed25519])

  AM_CONDITIONAL([ED25519], [test "x$enable_ed25519" != "xno"])
  AM_COND_IF([ED25519], [
    ED25519_SUBDIR=ed25519
    ED25519_LIBS="-L\$(top_builddir)/pdns/ext/$ED25519_SUBDIR/ -led25519"
  ],[
    ED25519_SUBDIR=
    ED25519_LIBS=
  ])

  AC_SUBST(ED25519_SUBDIR)
  AC_SUBST(ED25519_LIBS)
])
