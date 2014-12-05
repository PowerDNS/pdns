#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN

#include <boost/test/unit_test.hpp>
#include <boost/test/floating_point_comparison.hpp>
#include "iputils.hh"
#include "nameserver.hh"
#include "statbag.hh"
#include "packetcache.hh"
#include "arguments.hh"
#include <utility>
extern StatBag S;


BOOST_AUTO_TEST_SUITE(packetcache_cc)

BOOST_AUTO_TEST_CASE(test_PacketCacheSimple) {
  PacketCache PC;

  ::arg().set("max-cache-entries", "Maximum number of cache entries")="1000000";
  ::arg().set("cache-ttl","Seconds to store packets in the PacketCache")="20";
  ::arg().set("recursive-cache-ttl","Seconds to store packets for recursive queries in the PacketCache")="10";
  ::arg().set("negquery-cache-ttl","Seconds to store negative query results in the QueryCache")="60";
  ::arg().set("query-cache-ttl","Seconds to store query results in the QueryCache")="20";
  ::arg().set("recursor","If recursion is desired, IP address of a recursing nameserver")="no"; 

  S.declare("deferred-cache-inserts","Amount of cache inserts that were deferred because of maintenance");
  S.declare("deferred-cache-lookup","Amount of cache lookups that were deferred because of maintenance");


  BOOST_CHECK_EQUAL(PC.size(), 0);
  PC.insert("hello", QType(QType::A), PacketCache::QUERYCACHE, "something", 3600, 1);
  BOOST_CHECK_EQUAL(PC.size(), 1);
  PC.purge();
  BOOST_CHECK_EQUAL(PC.size(), 0);

  int counter=0;
  try {
    for(counter = 0; counter < 100000; ++counter) {
      PC.insert("hello "+boost::lexical_cast<string>(counter), QType(QType::A), PacketCache::QUERYCACHE, "something", 3600, 1);
    }

    BOOST_CHECK_EQUAL(PC.size(), counter);
    
    int delcounter=0;
    for(delcounter=0; delcounter < counter/100; ++delcounter) {
      PC.purge("hello "+boost::lexical_cast<string>(delcounter));
    }
    
    BOOST_CHECK_EQUAL(PC.size(), counter-delcounter);
    
    int matches=0;
    string entry;
    int expected=counter-delcounter;
    for(; delcounter < counter; ++delcounter) {
      if(PC.getEntry("hello "+boost::lexical_cast<string>(delcounter), QType(QType::A), PacketCache::QUERYCACHE, entry, 1)) {
	matches++;
      }
    }
    BOOST_CHECK_EQUAL(matches, expected);
    BOOST_CHECK_EQUAL(entry, "something");
  }
  catch(PDNSException& e) {
    cerr<<"Had error: "<<e.reason<<endl;
    throw;
  }

}

static PacketCache* g_PC;

static void *threadMangler(void* a)
try
{
  unsigned int offset=(unsigned int)(unsigned long)a;
  for(unsigned int counter=0; counter < 100000; ++counter)
    g_PC->insert("hello "+boost::lexical_cast<string>(counter+offset), QType(QType::A), PacketCache::QUERYCACHE, "something", 3600, 1);    
  return 0;
}
 catch(PDNSException& e) {
   cerr<<"Had error: "<<e.reason<<endl;
   throw;
 }

AtomicCounter g_missing;

static void *threadReader(void* a)
try
{
  unsigned int offset=(unsigned int)(unsigned long)a;
  string entry;
  for(unsigned int counter=0; counter < 100000; ++counter)
    if(!g_PC->getEntry("hello "+boost::lexical_cast<string>(counter+offset), QType(QType::A), PacketCache::QUERYCACHE, entry, 1)) {
	g_missing++;
    }
  return 0;
}
catch(PDNSException& e) {
  cerr<<"Had error in threadReader: "<<e.reason<<endl;
  throw;
}


BOOST_AUTO_TEST_CASE(test_PacketCacheThreaded) {
  try {
    PacketCache PC;
    g_PC=&PC;
    pthread_t tid[4];
    for(int i=0; i < 4; ++i) 
      pthread_create(&tid[i], 0, threadMangler, (void*)(i*1000000UL));
    void* res;
    for(int i=0; i < 4 ; ++i)
      pthread_join(tid[i], &res);
    
    BOOST_CHECK_EQUAL(PC.size() + S.read("deferred-cache-inserts"), 400000);
    BOOST_CHECK_SMALL(1.0*S.read("deferred-cache-inserts"), 10000.0);

    for(int i=0; i < 4; ++i) 
      pthread_create(&tid[i], 0, threadReader, (void*)(i*1000000UL));
    for(int i=0; i < 4 ; ++i)
      pthread_join(tid[i], &res);

    BOOST_CHECK_EQUAL(S.read("deferred-cache-inserts"), g_missing);
    BOOST_CHECK_EQUAL(S.read("deferred-cache-lookup"), 0);

  }
  catch(PDNSException& e) {
    cerr<<"Had error: "<<e.reason<<endl;
    throw;
  }
  
}


BOOST_AUTO_TEST_SUITE_END()
