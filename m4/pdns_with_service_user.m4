AC_DEFUN([PDNS_WITH_SERVICE_USER], [
  AC_MSG_CHECKING([What user and group will be used by service])
  AC_ARG_WITH([service-user],
    AS_HELP_STRING([--with-service-user], [User to use by service when running the service @<:@default=$1@:>@. Only the setuid setting and User in the systemd unit file are affected, the user is not created.]),
    [AC_SUBST([service_user], [$withval])],
    [AC_SUBST([service_user], [$1])]
  )

  AC_ARG_WITH([service-group],
    AS_HELP_STRING([--with-service-group], [Group to use by service when running the service @<:@default=$1@:>@. Only the setgid setting and Group in the systemd unit file are affected, the group is not created.]),
    [AC_SUBST([service_group], [$withval])],
    [AC_SUBST([service_group], [$1])]
  )

  AS_IF([test -z "$service_user"], [AC_MSG_ERROR([No service user has been defined!])], [ : ])
  AC_MSG_RESULT([$service_user])
])
