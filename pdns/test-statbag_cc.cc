#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN

#include <boost/test/unit_test.hpp>
#include <boost/assign/list_of.hpp>
#include <boost/foreach.hpp>
#include <boost/tuple/tuple.hpp>
#include "misc.hh"
#include "dns.hh"
#include "statbag.hh"

using std::string;

static void *threadMangler(void* a)
{
  AtomicCounter* ac = (AtomicCounter*)a;
  for(unsigned int n=0; n < 10000000; ++n)
    (*ac)++;
  return 0;
}

BOOST_AUTO_TEST_SUITE(misc_hh)

BOOST_AUTO_TEST_CASE(test_StatBagBasic) {
  StatBag s;
  s.declare("a", "description");
  s.declare("b", "description");
  s.declare("c", "description");
  s.inc("a");
  BOOST_CHECK_EQUAL(s.read("a"), 1);
  
  int n;
  for(n=0; n < 1000000; ++n)
    s.inc("b");

  BOOST_CHECK_EQUAL(s.read("b"), n);

  AtomicCounter* ac = s.getPointer("a");
  for(n=0; n < 1000000; ++n)
    (*ac)++;

  BOOST_CHECK_EQUAL(s.read("a"), n+1);

  AtomicCounter* acc = s.getPointer("c");
  pthread_t tid[4];
  for(int i=0; i < 4; ++i) 
    pthread_create(&tid[i], 0, threadMangler, (void*)acc);
  void* res;
  for(int i=0; i < 4 ; ++i)
    pthread_join(tid[i], &res);

  BOOST_CHECK_EQUAL(s.read("c"), 40000000U);
}


BOOST_AUTO_TEST_SUITE_END()

