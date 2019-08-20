#define BOOST_TEST_DYN_LINK

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


bool init_unit_test() {
  reportAllTypes();
  return true;
}

// entry point:
int main(int argc, char* argv[])
{
  return boost::unit_test::unit_test_main( &init_unit_test, argc, argv );
}
