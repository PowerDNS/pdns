#ifndef BOOST_TEST_DYN_LINK
#define BOOST_TEST_DYN_LINK
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <boost/test/unit_test.hpp>
#include "arguments.hh"
#include "auth-packetcache.hh"
#include "auth-querycache.hh"
#include "auth-zonecache.hh"
#include "statbag.hh"

StatBag S;
AuthPacketCache PC;
AuthQueryCache QC;
AuthZoneCache g_zoneCache;
uint16_t g_maxNSEC3Iterations{0};

ArgvMap& arg()
{
  static ArgvMap theArg;
  return theArg;
}

static bool init_unit_test()
{
  reportAllTypes();
  return true;
}

// entry point:
int main(int argc, char* argv[])
{
  setenv("BOOST_TEST_RANDOM", "1", 1); // NOLINT(concurrency-mt-unsafe)
  S.d_allowRedeclare = true;
  return boost::unit_test::unit_test_main(&init_unit_test, argc, argv);
}
