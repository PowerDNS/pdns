pkglib_LTLIBRARIES = libldapbackend.la

EXTRA_DIST = \
    OBJECTFILES \
    OBJECTLIBS \
    dnsdomain2.schema \
    pdns-domaininfo.schema

dist_doc_DATA = \
    dnsdomain2.schema \
    pdns-domaininfo.schema

libldapbackend_la_SOURCES = \
	ldapbackend.cc ldapbackend.hh \
	powerldap.cc powerldap.hh \
	utils.hh

libldapbackend_la_LDFLAGS = -module -avoid-version
libldapbackend_la_LIBADD = $(LDAP_LIBS)
