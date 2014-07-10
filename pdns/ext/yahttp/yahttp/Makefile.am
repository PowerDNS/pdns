AM_CPPFLAGS=$(BOOST_CPPFLAGS) @THREADFLAGS@
noinst_LTLIBRARIES=libyahttp.la

libyahttp_la_SOURCES=cookie.hpp exception.hpp reqresp.cpp reqresp.hpp router.cpp router.hpp url.hpp utility.hpp yahttp-config.h yahttp.hpp

yahttp-config.h:
	cat ../../../../config.h > yahttp-config.h
