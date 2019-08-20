AC_DEFUN([PDNS_CHECK_CASSANDRA], [
    AC_CHECK_TOOL([PKG_CONFIG], [pkg-config])
    AC_ARG_ENABLE([cassandra-static],
        [AS_HELP_STRING([--enable-cassandra-static],
            [Link with static cassandra client libraries])],
        [
            PKG_CHECK_MODULES([CASSANDRA], [cassandra_static],,
            [
                AC_MSG_ERROR([cassandra_static not found via pkg-config])
            ])
        ],
        [
            PKG_CHECK_MODULES([CASSANDRA], [cassandra],,
            [
                AC_MSG_ERROR([cassandra not found via pkg-config])
            ])
        ]
    )

    AC_MSG_CHECKING([whether DNSBackend has getDomainInfo() with 3 args])

    AC_COMPILE_IFELSE(
        [AC_LANG_SOURCE(
            [#include "pdns/dnsbackend.hh"
                bool (DNSBackend::*check)(const DNSName&, DomainInfo&, bool) = &DNSBackend::getDomainInfo;
            ]
        )],
        [AC_MSG_RESULT([yes]) AC_DEFINE([HAVE_DNSBACKEND_DOMAIN_INFO_WITH_SERIAL], [1], "Set if DNSBackend has getDomainInfo() method with 3 args")],
        [AC_MSG_RESULT([no])]
    )

])
