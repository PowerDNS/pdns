AM_CPPFLAGS=@THREADFLAGS@
EXTRA_DIST=OBJECTFILES OBJECTLIBS 

INCLUDES=-I/opt/mongo/include/mongo/

lib_LTLIBRARIES = libmongodbbackend.la

libmongodbbackend_la_SOURCES=mongodbbackend.cc mongodbbackend.hh minimal.cc slave.cc master.cc reload.cc private.cc dnssec.cc supermaster.cc crc32.cc
libmongodbbackend_la_LDFLAGS=-module -avoid-version -L/opt/mongo/lib64 $(BOOST_THREAD_LDFLAGS) $(BOOST_FILESYSTEM_LDFLAGS) $(BOOST_SYSTEM_LDFLAGS)  -lmongoclient $(BOOST_THREAD_LIBS) $(BOOST_FILESYSTEM_LIBS) $(BOOST_SYSTEM_LIBS) 

