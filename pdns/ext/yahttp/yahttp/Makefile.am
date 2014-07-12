AM_CPPFLAGS=$(BOOST_CPPFLAGS) @THREADFLAGS@
noinst_LTLIBRARIES=libyahttp.la

libyahttp_la_SOURCES=cookie.hpp exception.hpp reqresp.cpp reqresp.hpp router.cpp router.hpp url.hpp utility.hpp yahttp-config.h yahttp.hpp

reqresp.cpp: yahttp-config.h
router.cpp: yahttp-config.h

yahttp-config.h: ../../../../config.h
	cat ../../../../config.h > yahttp-config.h

clean-local: clean-local-check
.PHONY: clean-local-check

clean-local-check:
	test -f yahttp-config.h && rm yahttp-config.h || true
