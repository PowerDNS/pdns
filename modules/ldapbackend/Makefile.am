pkglib_LTLIBRARIES = libldapbackend.la

EXTRA_DIST = OBJECTFILES OBJECTLIBS

libldapbackend_la_SOURCES = \
	ldapbackend.cc ldapbackend.hh \
	native.cc master.cc \
	powerldap.cc powerldap.hh \
	utils.hh exceptions.hh \
	ldaputils.hh ldaputils.cc \
	ldapauthenticator.hh ldapauthenticator_p.hh ldapauthenticator.cc

libldapbackend_la_LDFLAGS = -module -avoid-version
libldapbackend_la_LIBADD = $(LDAP_LIBS) $(KRB5_LIBS)
