AM_CPPFLAGS=@THREADFLAGS@

EXTRA_DIST=OBJECTFILES OBJECTLIBS

lib_LTLIBRARIES = libldapbackend.la
libldapbackend_la_CPPFLAGS = -DLDAP_DEPRECATED
libldapbackend_la_LIBADD = -lldap
libldapbackend_la_SOURCES = \
	ldapbackend.cc ldapbackend.hh \
	powerldap.hh powerldap.cc \
	utils.hh



