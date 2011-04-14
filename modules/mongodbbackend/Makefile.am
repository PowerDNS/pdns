AM_CPPFLAGS=@THREADFLAGS@
EXTRA_DIST=OBJECTFILES OBJECTLIBS 

INCLUDES=-I/opt/mongo/include/mongo/

lib_LTLIBRARIES = libmongodbbackend.la

libmongodbbackend_la_SOURCES=mongodbbackend.cc mongodbbackend.hh minimal.cc slave.cc master.cc reload.cc private.cc dnssec.cc supermaster.cc crc32.cc
libmongodbbackend_la_LDFLAGS=-module -avoid-version -L/opt/mongo/lib64 -lmongoclient -lboost_thread -lboost_filesystem -lboost_system

