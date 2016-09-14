pkglib_LTLIBRARIES = libldapbackend.la

EXTRA_DIST = OBJECTFILES OBJECTLIBS

libldapbackend_la_SOURCES = \
	ldapbackend.cc ldapbackend.hh \
	powerldap.cc powerldap.hh \
	utils.hh exceptions.hh \
	ldaputils.hh ldaputils.cc

libldapbackend_la_LDFLAGS = -module -avoid-version
libldapbackend_la_LIBADD = $(LDAP_LIBS)
