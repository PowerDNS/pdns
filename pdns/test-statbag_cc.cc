#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <boost/test/unit_test.hpp>
#include <boost/assign/list_of.hpp>

#include <boost/tuple/tuple.hpp>
#include <stdint.h>
#include "misc.hh"
#include "dns.hh"
#include "statbag.hh"

using std::string;

static void *threadMangler(void* a)
{
  AtomicCounter* ac=(AtomicCounter*)a;
  for(unsigned int n=0; n < 1000000; ++n)
    (*ac)++;
  return 0;
}

static void *threadMangler2(void* a)
{
  StatBag* S = (StatBag*)a;
  for(unsigned int n=0; n < 1000000; ++n)
    S->inc("c");
  return 0;
}



BOOST_AUTO_TEST_SUITE(test_misc_hh)

BOOST_AUTO_TEST_CASE(test_StatBagBasic) {
  StatBag s;
  s.declare("a", "description");
  s.declare("b", "description");
  s.declare("c", "description");
  s.inc("a");
  BOOST_CHECK_EQUAL(s.read("a"), 1UL);
  
  unsigned long n;
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

  BOOST_CHECK_EQUAL(s.read("c"), 4000000U);
 
  s.set("c", 0);

  for(int i=0; i < 4; ++i) 
    pthread_create(&tid[i], 0, threadMangler2, (void*)&s);

  for(int i=0; i < 4 ; ++i)
    pthread_join(tid[i], &res);

  BOOST_CHECK_EQUAL(s.read("c"), 4000000U);


  s.set("c", 1ULL<<31);
  BOOST_CHECK_EQUAL(s.read("c"), (1ULL<<31) );
  s.inc("c");
  BOOST_CHECK_EQUAL(s.read("c"), (1ULL<<31) +1 );

#ifdef UINTPTR_MAX  
#if UINTPTR_MAX > 0xffffffffULL
    BOOST_CHECK_EQUAL(sizeof(AtomicCounterInner), 8U);
    s.set("c", 1ULL<<33);
    BOOST_CHECK_EQUAL(s.read("c"), (1ULL<<33) );
    s.inc("c");
    BOOST_CHECK_EQUAL(s.read("c"), (1ULL<<33) +1 );

    s.set("c", ~0ULL);
    BOOST_CHECK_EQUAL(s.read("c"), 0xffffffffffffffffULL );
    s.inc("c");
    BOOST_CHECK_EQUAL(s.read("c"), 0UL );
#else
    BOOST_CHECK_EQUAL(sizeof(AtomicCounterInner), 4U);
    BOOST_CHECK_EQUAL(~0UL, 0xffffffffUL);
    s.set("c", ~0UL);
    BOOST_CHECK_EQUAL(s.read("c"), 0xffffffffUL );
    s.inc("c");
    BOOST_CHECK_EQUAL(s.read("c"), 0UL );
#endif
#endif
}


BOOST_AUTO_TEST_SUITE_END()

