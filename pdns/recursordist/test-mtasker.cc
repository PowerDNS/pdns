#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <boost/test/unit_test.hpp>
#include <boost/test/floating_point_comparison.hpp>
#include "mtasker.hh"

BOOST_AUTO_TEST_SUITE(mtasker_cc)

static int g_result;

static void doSomething(void* p)
{
  MTasker<>* mt = reinterpret_cast<MTasker<>*>(p);
  int i=12, o;
  if (mt->waitEvent(i, &o) == 1)
    g_result = o;
}

BOOST_AUTO_TEST_CASE(test_Simple) {
  MTasker<> mt;
  mt.makeThread(doSomething, &mt);
  struct timeval now;
  gettimeofday(&now, 0);
  bool first=true;
  int o=24;
  for(;;) {
    while(mt.schedule(&now));
    if(first) {
      mt.sendEvent(12, &o);
      first=false;
    }
    if(mt.noProcesses())
      break;
  }
  BOOST_CHECK_EQUAL(g_result, o);
}

static void willThrow(void* p)
{
  throw std::runtime_error("Help!");
}


BOOST_AUTO_TEST_CASE(test_MtaskerException) {
  BOOST_CHECK_THROW( {
      MTasker<> mt;
      mt.makeThread(willThrow, 0);
      struct timeval now;
      
      for(;;) {
	mt.schedule(&now);
      }
    }, std::exception);
}
BOOST_AUTO_TEST_SUITE_END()
