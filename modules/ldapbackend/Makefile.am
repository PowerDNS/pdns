AM_CPPFLAGS=$(THREADFLAGS) $(BOOST_CPPFLAGS)

EXTRA_DIST = OBJECTFILES OBJECTLIBS

pkglib_LTLIBRARIES = libldapbackend.la
libldapbackend_la_SOURCES = ldapbackend.cc ldapbackend.hh powerldap.hh powerldap.cc utils.hh
libldapbackend_la_LDFLAGS =-module -avoid-version
libldapbackend_la_LIBADD =-l$(LIBLDAP)
