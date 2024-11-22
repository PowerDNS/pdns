pkglib_LTLIBRARIES = libldapbackend.la

AM_CPPFLAGS += $(LIBCRYPTO_INCLUDES)

EXTRA_DIST = \
    OBJECTFILES \
    OBJECTLIBS \
    dnsdomain2.schema \
    pdns-domaininfo.schema

dist_doc_DATA = \
    dnsdomain2.schema \
    pdns-domaininfo.schema

libldapbackend_la_SOURCES = \
	exceptions.hh \
	ldapauthenticator.hh ldapauthenticator_p.hh ldapauthenticator.cc \
	ldapbackend.cc ldapbackend.hh \
	ldaputils.hh ldaputils.cc \
	native.cc \
	powerldap.cc powerldap.hh \
	primary.cc \
	utils.hh

if LDAPBACKEND_DYNMODULE
libldapbackend_la_LDFLAGS = -module -avoid-version
else
libldapbackend_la_LDFLAGS = -static -avoid-version
endif
libldapbackend_la_LIBADD = $(LDAP_LIBS) $(KRB5_LIBS)
