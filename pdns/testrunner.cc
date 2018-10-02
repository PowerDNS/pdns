#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MAIN
#define BOOST_TEST_MODULE unit

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <boost/test/unit_test.hpp>
#include "arguments.hh"
#include "auth-packetcache.hh"
#include "auth-querycache.hh"
#include "statbag.hh"
StatBag S;
AuthPacketCache PC;
AuthQueryCache QC;

ArgvMap &arg()
{
  static ArgvMap theArg;
  return theArg;
}
