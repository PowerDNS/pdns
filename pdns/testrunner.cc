#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MAIN
#define BOOST_TEST_MODULE unit

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "packetcache.hh"
StatBag S;
PacketCache PC;

#include <boost/test/unit_test.hpp>
