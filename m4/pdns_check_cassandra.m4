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
])
