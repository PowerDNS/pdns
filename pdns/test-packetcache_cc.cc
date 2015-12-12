#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
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
  PC.insert(DNSName("hello"), QType(QType::A), PacketCache::QUERYCACHE, "something", 3600, 1);
  BOOST_CHECK_EQUAL(PC.size(), 1);
  PC.purge();
  BOOST_CHECK_EQUAL(PC.size(), 0);

  int counter=0;
  try {
    for(counter = 0; counter < 100000; ++counter) {
      DNSName a=DNSName("hello ")+DNSName(std::to_string(counter));
      BOOST_CHECK_EQUAL(DNSName(a.toString()), a);

      PC.insert(a, QType(QType::A), PacketCache::QUERYCACHE, "something", 3600, 1);
      if(!PC.purge(a.toString()))
	BOOST_FAIL("Could not remove entry we just added to packet cache!");
      PC.insert(a, QType(QType::A), PacketCache::QUERYCACHE, "something", 3600, 1);
    }

    BOOST_CHECK_EQUAL(PC.size(), counter);
    
    int delcounter=0;
    for(delcounter=0; delcounter < counter/100; ++delcounter) {
      DNSName a=DNSName("hello ")+DNSName(std::to_string(delcounter));
      PC.purge(a.toString());
    }
    
    BOOST_CHECK_EQUAL(PC.size(), counter-delcounter);
    
    int matches=0;
    vector<DNSResourceRecord> entry;
    int expected=counter-delcounter;
    for(; delcounter < counter; ++delcounter) {
      if(PC.getEntry(DNSName("hello ")+DNSName(std::to_string(delcounter)), QType(QType::A), PacketCache::QUERYCACHE, entry, 1)) {
	matches++;
      }
    }
    BOOST_CHECK_EQUAL(matches, expected);
    //    BOOST_CHECK_EQUAL(entry, "something");
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
    g_PC->insert(DNSName("hello ")+DNSName(std::to_string(counter+offset)), QType(QType::A), PacketCache::QUERYCACHE, "something", 3600, 1);    
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
  vector<DNSResourceRecord> entry;
  for(unsigned int counter=0; counter < 100000; ++counter)
    if(!g_PC->getEntry(DNSName("hello ")+DNSName(std::to_string(counter+offset)), QType(QType::A), PacketCache::QUERYCACHE, entry, 1)) {
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

    BOOST_CHECK(S.read("deferred-cache-inserts") + S.read("deferred-cache-lookup") >= g_missing);
    //    BOOST_CHECK_EQUAL(S.read("deferred-cache-lookup"), 0); // cache cleaning invalidates this
  }
  catch(PDNSException& e) {
    cerr<<"Had error: "<<e.reason<<endl;
    throw;
  }
  
}

bool g_stopCleaning;
static void *cacheCleaner(void*)
try
{
  while(!g_stopCleaning) {
    g_PC->cleanup();
  }

  return 0;
}
catch(PDNSException& e) {
  cerr<<"Had error in threadReader: "<<e.reason<<endl;
  throw;
}

BOOST_AUTO_TEST_CASE(test_PacketCacheClean) {
  try {
    PacketCache PC;

    for(unsigned int counter = 0; counter < 1000000; ++counter) {
      PC.insert(DNSName("hello ")+DNSName(std::to_string(counter)), QType(QType::A), PacketCache::QUERYCACHE, "something", 1, 1);
    }

    sleep(1);
    
    g_PC=&PC;
    pthread_t tid[4];

    ::arg().set("max-cache-entries")="10000";

    pthread_create(&tid[0], 0, threadReader, (void*)(0*1000000UL));
    pthread_create(&tid[1], 0, threadReader, (void*)(1*1000000UL));
    pthread_create(&tid[2], 0, threadReader, (void*)(2*1000000UL));
    //    pthread_create(&tid[2], 0, threadMangler, (void*)(0*1000000UL));
    pthread_create(&tid[3], 0, cacheCleaner, 0);

    void *res;
    for(int i=0; i < 3 ; ++i)
      pthread_join(tid[i], &res);
    g_stopCleaning=true;
    pthread_join(tid[3], &res);
  }
  catch(PDNSException& e) {
    cerr<<"Had error in threadReader: "<<e.reason<<endl;
    throw;
  }
}

BOOST_AUTO_TEST_CASE(test_PacketCachePacket) {
  try {
    ::arg().setSwitch("no-shuffle","Set this to prevent random shuffling of answers - for regression testing")="off";

    PacketCache PC;
    vector<uint8_t> pak;
    vector<pair<uint16_t,string > > opts;

    DNSPacketWriter pw(pak, DNSName("www.powerdns.com"), QType::A);
    DNSPacket q, r, r2;
    q.parse((char*)&pak[0], pak.size());

    pak.clear();
    DNSPacketWriter pw2(pak, DNSName("www.powerdns.com"), QType::A);
    pw2.startRecord(DNSName("www.powerdns.com"), QType::A, 16, 1, DNSResourceRecord::ANSWER);
    pw2.xfrIP(htonl(0x7f000001));
    pw2.commit();

    r.parse((char*)&pak[0], pak.size());

    PC.insert(&q, &r, false, 3600);

    BOOST_CHECK_EQUAL(PC.get(&q, &r2, false), 1);
    BOOST_CHECK_EQUAL(r2.qdomain, r.qdomain);

    PC.purge("www.powerdns.com");
    BOOST_CHECK_EQUAL(PC.get(&q, &r2, false), 0);

    PC.insert(&q, &r, false, 3600);
    BOOST_CHECK_EQUAL(PC.get(&q, &r2, false), 1);
    BOOST_CHECK_EQUAL(r2.qdomain, r.qdomain);
    PC.purge("com$");
    BOOST_CHECK_EQUAL(PC.get(&q, &r2, false), 0);

    PC.insert(&q, &r, false, 3600);
    BOOST_CHECK_EQUAL(PC.get(&q, &r2, false), 1);
    BOOST_CHECK_EQUAL(r2.qdomain, r.qdomain);
    PC.purge("powerdns.com$");
    BOOST_CHECK_EQUAL(PC.get(&q, &r2, false), 0);

    PC.insert(&q, &r, false, 3600);
    BOOST_CHECK_EQUAL(PC.get(&q, &r2, false), 1);
    BOOST_CHECK_EQUAL(r2.qdomain, r.qdomain);
    PC.purge("www.powerdns.com$");
    BOOST_CHECK_EQUAL(PC.get(&q, &r2, false), 0);

    PC.insert(&q, &r, false, 3600);
    BOOST_CHECK_EQUAL(PC.get(&q, &r2, true), 0);
    PC.purge("www.powerdns.com$");

    PC.insert(&q, &r, true, 3600);
    BOOST_CHECK_EQUAL(PC.get(&q, &r2, false), 0);
    PC.purge("www.powerdns.com$");

    PC.insert(&q, &r, true, 3600);
    PC.purge("www.powerdns.net");
    BOOST_CHECK_EQUAL(PC.get(&q, &r2, true), 1);
    BOOST_CHECK_EQUAL(r2.qdomain, r.qdomain);
    PC.purge("net$");
    BOOST_CHECK_EQUAL(PC.get(&q, &r2, true), 1);
    BOOST_CHECK_EQUAL(r2.qdomain, r.qdomain);
    PC.purge("www.powerdns.com$");
    BOOST_CHECK_EQUAL(PC.size(), 0);
  }
  catch(PDNSException& e) {
    cerr<<"Had error in threadReader: "<<e.reason<<endl;
    throw;
  }
} 

BOOST_AUTO_TEST_SUITE_END()
