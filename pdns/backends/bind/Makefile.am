INCLUDES=-I../..
noinst_LTLIBRARIES = libbindbackend.la

libbindbackend_la_SOURCES=bindbackend.cc bindbackend.hh bindparser.yy \
bindlexer.l zoneparser2.cc ../../misc.cc huffman.cc huffman.hh zoneparser.hh \
bindparser.hh ../../unix_utility.cc

bin_PROGRAMS = zone2sql

zone2sql_SOURCES=bindparser.yy bindlexer.l zoneparser2.cc \
../../arguments.cc ../../logger.cc zone2sql.cc ../../statbag.cc ../../misc.cc \
../../unix_utility.cc ../../qtype.cc

zone2sql_LDFLAGS=@THREADFLAGS@

LFLAGS = -s -i
YFLAGS = -d --verbose --debug
