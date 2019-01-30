Yet Another HTTP Library
========================

YaHTTP aims to be a pure http request/response parser that has no IO ties. It is intended to be used on small-footprint applications and other utilities that want to use HTTP over something else than network IO.

[![Build Status](https://travis-ci.org/cmouse/yahttp.svg?branch=master)](https://travis-ci.org/cmouse/yahttp)
[![Coverity Scan Build Status](https://scan.coverity.com/projects/2161/badge.svg)](https://scan.coverity.com/projects/2161)
[![Coverage Status](https://coveralls.io/repos/github/cmouse/yahttp/badge.svg)](https://coveralls.io/github/cmouse/yahttp)

WARNINGS
--------
If you are upgrading from version before May 02, 2014 - *PLEASE BE SURE TO CHECK THAT EVERYTHING WORKS AS EXPECTED*. There has been complete overhaul of the library and many things have changed. 

NOTES
-----
Do not use resp = req, or resp(req) to build the response object, despite it being supported. This will cause request headers to get duplicated. Also, you *must* set response#version to request#version if you intend to support older than HTTP/1.1 clients. Set response#status to at least 200, it won't be done for you. No Server or Product token is sent either, you can add those if you want. 

If you do not want to send chunked responses, set content-length header. Setting this header will always disable chunked responses. This will also happen if you downgrade your responses to version 10 or 9.

Integration guide
-----------------

Here are some instructions on how to integrate YaHTTP into your project. 

With automake and libtool
-------------------------

If you don't need router or any of the C++11 features, you can just create empty yahttp-config.h, or symlink it to your project's config.h for the yahttp.hpp to include. Then just put this stuff into it's own folder and create Makefile.am with following contents (you can change the compilation flags):

```
noinst_LTLIBRARIES=libyahttp.la
libyahttp_la_CXXFLAGS=$(RELRO_CFLAGS) $(PIE_CFLAGS) -D__STRICT_ANSI__
libyahttp_la_SOURCES=cookie.hpp exception.hpp reqresp.cpp reqresp.hpp router.cpp router.hpp url.hpp utility.hpp yahttp.hpp
```

You can define RELRO and PIE to match your project. 

To compile your project use -Lpath/to/yahttp -lyahttp

If you need router, additionally check for boost or C++11 and replace yahttp-config.h to config.h in yahttp.hpp or add relevant options to your compiler CXXFLAGS. See below for the flags.

Without automake
----------------

Create simple Makefile with contents for C++11:

```
OBJECTS=reqresp.o router.o
CXX=gcc
CXXFLAGS=-W -Wall -DHAVE_CXX11 -std=c++11 
```

Or create simple Makefile with contents for boost:

```
OBJECTS=reqresp.o router.o
CXX=gcc
CXXFLAGS=-W -Wall -DHAVE_BOOST 
```

Or if you don't need either one, just:

```
OBJECTS=reqresp.o 
CXX=gcc
CXXFLAGS=-W -Wall
```

YaHTTP include files can be placed where the rest of your includes are. Then just add your own code there and it should work just fine. 
