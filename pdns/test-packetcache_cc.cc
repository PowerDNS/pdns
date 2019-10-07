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
#include "auth-packetcache.hh"
#include "auth-querycache.hh"
#include "arguments.hh"
#include <utility>
extern StatBag S;

BOOST_AUTO_TEST_SUITE(test_packetcache_cc)

BOOST_AUTO_TEST_CASE(test_AuthQueryCacheSimple) {
  AuthQueryCache QC;
  QC.setMaxEntries(1000000);

  vector<DNSZoneRecord> records;

  BOOST_CHECK_EQUAL(QC.size(), 0U);
  QC.insert(DNSName("hello"), QType(QType::A), records, 3600, 1);
  BOOST_CHECK_EQUAL(QC.size(), 1U);
  BOOST_CHECK_EQUAL(QC.purge(), 1U);
  BOOST_CHECK_EQUAL(QC.size(), 0U);

  uint64_t counter=0;
  try {
    for(counter = 0; counter < 100000; ++counter) {
      DNSName a=DNSName("hello ")+DNSName(std::to_string(counter));
      BOOST_CHECK_EQUAL(DNSName(a.toString()), a);

      QC.insert(a, QType(QType::A), records, 3600, 1);
      if(!QC.purge(a.toString()))
	BOOST_FAIL("Could not remove entry we just added to the query cache!");
      QC.insert(a, QType(QType::A), records, 3600, 1);
    }

    BOOST_CHECK_EQUAL(QC.size(), counter);

    uint64_t delcounter=0;
    for(delcounter=0; delcounter < counter/100; ++delcounter) {
      DNSName a=DNSName("hello ")+DNSName(std::to_string(delcounter));
      BOOST_CHECK_EQUAL(QC.purge(a.toString()), 1U);
    }

    BOOST_CHECK_EQUAL(QC.size(), counter-delcounter);

    int64_t matches=0;
    vector<DNSZoneRecord> entry;
    int64_t expected=counter-delcounter;
    for(; delcounter < counter; ++delcounter) {
      if(QC.getEntry(DNSName("hello ")+DNSName(std::to_string(delcounter)), QType(QType::A), entry, 1)) {
	matches++;
      }
    }
    BOOST_CHECK_EQUAL(matches, expected);
    BOOST_CHECK_EQUAL(entry.size(), records.size());
  }
  catch(PDNSException& e) {
    cerr<<"Had error: "<<e.reason<<endl;
    throw;
  }

}

static AuthQueryCache* g_QC;
static AtomicCounter g_QCmissing;

static void *threadQCMangler(void* a)
try
{
  vector<DNSZoneRecord> records;
  unsigned int offset=(unsigned int)(unsigned long)a;
  for(unsigned int counter=0; counter < 100000; ++counter)
    g_QC->insert(DNSName("hello ")+DNSName(std::to_string(counter+offset)), QType(QType::A), records, 3600, 1);
  return 0;
}
 catch(PDNSException& e) {
   cerr<<"Had error: "<<e.reason<<endl;
   throw;
 }

static void *threadQCReader(void* a)
try
{
  unsigned int offset=(unsigned int)(unsigned long)a;
  vector<DNSZoneRecord> entry;
  for(unsigned int counter=0; counter < 100000; ++counter)
    if(!g_QC->getEntry(DNSName("hello ")+DNSName(std::to_string(counter+offset)), QType(QType::A), entry, 1)) {
      g_QCmissing++;
    }
  return 0;
}
catch(PDNSException& e) {
  cerr<<"Had error in threadQCReader: "<<e.reason<<endl;
  throw;
}

BOOST_AUTO_TEST_CASE(test_QueryCacheThreaded) {
  try {
    g_QCmissing = 0;
    AuthQueryCache QC;
    QC.setMaxEntries(1000000);
    g_QC=&QC;
    pthread_t tid[4];
    for(int i=0; i < 4; ++i)
      pthread_create(&tid[i], 0, threadQCMangler, (void*)(i*1000000UL));
    void* res;
    for(int i=0; i < 4 ; ++i)
      pthread_join(tid[i], &res);

    BOOST_CHECK_EQUAL(QC.size() + S.read("deferred-cache-inserts"), 400000U);
    BOOST_CHECK_SMALL(1.0*S.read("deferred-cache-inserts"), 10000.0);

    for(int i=0; i < 4; ++i)
      pthread_create(&tid[i], 0, threadQCReader, (void*)(i*1000000UL));
    for(int i=0; i < 4 ; ++i)
      pthread_join(tid[i], &res);

    BOOST_CHECK(S.read("deferred-cache-inserts") + S.read("deferred-cache-lookup") >= g_QCmissing);
    //    BOOST_CHECK_EQUAL(S.read("deferred-cache-lookup"), 0); // cache cleaning invalidates this
  }
  catch(PDNSException& e) {
    cerr<<"Had error: "<<e.reason<<endl;
    throw;
  }

}

static AuthPacketCache* g_PC;
static AtomicCounter g_PCmissing;

static void *threadPCMangler(void* a)
try
{
  unsigned int offset=(unsigned int)(unsigned long)a;
  for(unsigned int counter=0; counter < 100000; ++counter) {
    vector<uint8_t> pak;
    DNSName qname = DNSName("hello ")+DNSName(std::to_string(counter+offset));

    DNSPacketWriter pw(pak, qname, QType::A);
    DNSPacket q(true);
    q.parse((char*)&pak[0], pak.size());

    pak.clear();
    DNSPacketWriter pw2(pak, qname, QType::A);
    pw2.startRecord(qname, QType::A, 3600, QClass::IN, DNSResourceRecord::ANSWER);
    pw2.xfrIP(htonl(0x7f000001));
    pw2.commit();

    DNSPacket r(false);
    r.parse((char*)&pak[0], pak.size());

    /* this step is necessary to get a valid hash
       we directly compute the hash instead of querying the
       cache because 1/ it's faster 2/ no deferred-lookup issues
    */
    q.setHash(g_PC->canHashPacket(q.getString()));

    const unsigned int maxTTL = 3600;
    g_PC->insert(q, r, maxTTL);
  }

  return 0;
}
 catch(PDNSException& e) {
   cerr<<"Had error: "<<e.reason<<endl;
   throw;
 }

static void *threadPCReader(void* a)
try
{
  unsigned int offset=(unsigned int)(unsigned long)a;
  vector<DNSZoneRecord> entry;
  for(unsigned int counter=0; counter < 100000; ++counter) {
    vector<uint8_t> pak;
    DNSName qname = DNSName("hello ")+DNSName(std::to_string(counter+offset));

    DNSPacketWriter pw(pak, qname, QType::A);
    DNSPacket q(true);
    q.parse((char*)&pak[0], pak.size());
    DNSPacket r(false);

    if(!g_PC->get(q, r)) {
      g_PCmissing++;
    }
  }

  return 0;
}
catch(PDNSException& e) {
  cerr<<"Had error in threadPCReader: "<<e.reason<<endl;
  throw;
}

BOOST_AUTO_TEST_CASE(test_PacketCacheThreaded) {
  try {
    AuthPacketCache PC;
    PC.setMaxEntries(1000000);
    PC.setTTL(3600);

    g_PC=&PC;
    g_PCmissing = 0;
    pthread_t tid[4];
    for(int i=0; i < 4; ++i)
      pthread_create(&tid[i], 0, threadPCMangler, (void*)(i*1000000UL));
    void* res;
    for(int i=0; i < 4 ; ++i)
      pthread_join(tid[i], &res);

    BOOST_CHECK_EQUAL(PC.size() + S.read("deferred-packetcache-inserts"), 400000UL);
    BOOST_CHECK_EQUAL(S.read("deferred-packetcache-lookup"), 0UL);
    BOOST_CHECK_SMALL(1.0*S.read("deferred-packetcache-inserts"), 10000.0);

    for(int i=0; i < 4; ++i)
      pthread_create(&tid[i], 0, threadPCReader, (void*)(i*1000000UL));
    for(int i=0; i < 4 ; ++i)
      pthread_join(tid[i], &res);

/*
    cerr<<"Misses: "<<S.read("packetcache-miss")<<endl;
    cerr<<"Hits: "<<S.read("packetcache-hit")<<endl;
    cerr<<"Deferred inserts: "<<S.read("deferred-packetcache-inserts")<<endl;
    cerr<<"Deferred lookups: "<<S.read("deferred-packetcache-lookup")<<endl;
    cerr<<g_PCmissing<<endl;
    cerr<<PC.size()<<endl;
*/

    BOOST_CHECK_EQUAL(g_PCmissing + S.read("packetcache-hit"), 400000UL);
    BOOST_CHECK_EQUAL(S.read("deferred-packetcache-inserts") + S.read("deferred-packetcache-lookup"), g_PCmissing);
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
    g_QC->cleanup();
  }

  return 0;
}
catch(PDNSException& e) {
  cerr<<"Had error in cacheCleaner: "<<e.reason<<endl;
  throw;
}

BOOST_AUTO_TEST_CASE(test_QueryCacheClean) {
  try {
    AuthQueryCache QC;
    QC.setMaxEntries(10000);
    vector<DNSZoneRecord> records;

    for(unsigned int counter = 0; counter < 1000000; ++counter) {
      QC.insert(DNSName("hello ")+DNSName(std::to_string(counter)), QType(QType::A), records, 1, 1);
    }

    sleep(1);

    g_QC=&QC;
    pthread_t tid[4];

    pthread_create(&tid[0], 0, threadQCReader, (void*)(0*1000000UL));
    pthread_create(&tid[1], 0, threadQCReader, (void*)(1*1000000UL));
    pthread_create(&tid[2], 0, threadQCReader, (void*)(2*1000000UL));
    //    pthread_create(&tid[2], 0, threadMangler, (void*)(0*1000000UL));
    pthread_create(&tid[3], 0, cacheCleaner, 0);

    void *res;
    for(int i=0; i < 3 ; ++i)
      pthread_join(tid[i], &res);
    g_stopCleaning=true;
    pthread_join(tid[3], &res);
  }
  catch(PDNSException& e) {
    cerr<<"Had error in test_QueryCacheClean: "<<e.reason<<endl;
    throw;
  }
}

BOOST_AUTO_TEST_CASE(test_AuthPacketCache) {
  try {
    ::arg().setSwitch("no-shuffle","Set this to prevent random shuffling of answers - for regression testing")="off";

    AuthPacketCache PC;
    PC.setTTL(20);
    PC.setMaxEntries(100000);

    vector<uint8_t> pak;
    DNSPacket q(true), differentIDQ(true), ednsQ(true), ednsVersion42(true), ednsDO(true), ecs1(true), ecs2(true), ecs3(true);
    DNSPacket r(false), r2(false);

    {
      DNSPacketWriter pw(pak, DNSName("www.powerdns.com"), QType::A);
      q.parse((char*)&pak[0], pak.size());

      differentIDQ.parse((char*)&pak[0], pak.size());
      differentIDQ.setID(4242);

      pw.addOpt(512, 0, 0);
      pw.commit();
      ednsQ.parse((char*)&pak[0], pak.size());

      pak.clear();
    }

    DNSPacketWriter::optvect_t opts;
    EDNSSubnetOpts ecsOpts;
    {
      DNSPacketWriter pw(pak, DNSName("www.powerdns.com"), QType::A);
      pw.addOpt(512, 0, 0, DNSPacketWriter::optvect_t(), 42);
      pw.commit();
      ednsVersion42.parse((char*)&pak[0], pak.size());
      pak.clear();
    }

    {
      DNSPacketWriter pw(pak, DNSName("www.powerdns.com"), QType::A);
      pw.addOpt(512, 0, EDNSOpts::DNSSECOK);
      pw.commit();
      ednsDO.parse((char*)&pak[0], pak.size());
      pak.clear();
    }

    {
      ecsOpts.source = Netmask(ComboAddress("192.0.2.1"), 32);
      opts.push_back(make_pair(EDNSOptionCode::ECS, makeEDNSSubnetOptsString(ecsOpts)));
      DNSPacketWriter pw(pak, DNSName("www.powerdns.com"), QType::A);
      pw.addOpt(512, 0, 0, opts);
      pw.commit();
      ecs1.parse((char*)&pak[0], pak.size());
      pak.clear();
      opts.clear();
    }

    {
      DNSPacketWriter pw(pak, DNSName("www.powerdns.com"), QType::A);
      ecsOpts.source = Netmask(ComboAddress("192.0.2.2"), 32);
      opts.push_back(make_pair(EDNSOptionCode::ECS, makeEDNSSubnetOptsString(ecsOpts)));
      pw.addOpt(512, 0, 0, opts);
      pw.commit();
      ecs2.parse((char*)&pak[0], pak.size());
      pak.clear();
      opts.clear();
    }

    {
      DNSPacketWriter pw(pak, DNSName("www.powerdns.com"), QType::A);
      ecsOpts.source = Netmask(ComboAddress("192.0.2.3"), 16);
      opts.push_back(make_pair(EDNSOptionCode::ECS, makeEDNSSubnetOptsString(ecsOpts)));
      pw.addOpt(512, 0, 0, opts);
      pw.commit();
      ecs3.parse((char*)&pak[0], pak.size());
      pak.clear();
      opts.clear();
    }

    {
      DNSPacketWriter pw(pak, DNSName("www.powerdns.com"), QType::A);
      pw.startRecord(DNSName("www.powerdns.com"), QType::A, 16, 1, DNSResourceRecord::ANSWER);
      pw.xfrIP(htonl(0x7f000001));
      pw.commit();

      r.parse((char*)&pak[0], pak.size());
    }

    /* this call is required so the correct hash is set into q->d_hash */
    BOOST_CHECK_EQUAL(PC.get(q, r2), false);

    PC.insert(q, r, 3600);
    BOOST_CHECK_EQUAL(PC.size(), 1U);

    BOOST_CHECK_EQUAL(PC.get(q, r2), true);
    BOOST_CHECK_EQUAL(r2.qdomain, r.qdomain);

    /* different QID, still should match */
    BOOST_CHECK_EQUAL(PC.get(differentIDQ, r2), true);
    BOOST_CHECK_EQUAL(r2.qdomain, r.qdomain);

    /* with EDNS, should not match */
    BOOST_CHECK_EQUAL(PC.get(ednsQ, r2), false);
    /* inserting the EDNS-enabled one too */
    PC.insert(ednsQ, r, 3600);
    BOOST_CHECK_EQUAL(PC.size(), 2U);

    /* different EDNS versions, should not match */
    BOOST_CHECK_EQUAL(PC.get(ednsVersion42, r2), false);

    /* EDNS DO set, should not match */
    BOOST_CHECK_EQUAL(PC.get(ednsDO, r2), false);

    /* EDNS Client Subnet set, should not match
       since not only we don't skip the actual option, but the
       total EDNS opt RR is still different. */
    BOOST_CHECK_EQUAL(PC.get(ecs1, r2), false);

    /* inserting the version with ECS Client Subnet set,
     it should NOT replace the existing EDNS one. */
    PC.insert(ecs1, r, 3600);
    BOOST_CHECK_EQUAL(PC.size(), 3U);

    /* different subnet of same size, should NOT match
     since we don't skip the option */
    BOOST_CHECK_EQUAL(PC.get(ecs2, r2), false);
    BOOST_CHECK_EQUAL(r2.qdomain, r.qdomain);

    /* different subnet of different size, should NOT match. */
    BOOST_CHECK_EQUAL(PC.get(ecs3, r2), false);

    BOOST_CHECK_EQUAL(PC.purge("www.powerdns.com"), 3U);
    BOOST_CHECK_EQUAL(PC.get(q, r2), false);
    BOOST_CHECK_EQUAL(PC.size(), 0U);

    PC.insert(q, r, 3600);
    BOOST_CHECK_EQUAL(PC.size(), 1U);
    BOOST_CHECK_EQUAL(PC.get(q, r2), true);
    BOOST_CHECK_EQUAL(r2.qdomain, r.qdomain);
    BOOST_CHECK_EQUAL(PC.purge("com$"), 1U);
    BOOST_CHECK_EQUAL(PC.get(q, r2), false);
    BOOST_CHECK_EQUAL(PC.size(), 0U);

    PC.insert(q, r, 3600);
    BOOST_CHECK_EQUAL(PC.size(), 1U);
    BOOST_CHECK_EQUAL(PC.get(q, r2), true);
    BOOST_CHECK_EQUAL(r2.qdomain, r.qdomain);
    BOOST_CHECK_EQUAL(PC.purge("powerdns.com$"), 1U);
    BOOST_CHECK_EQUAL(PC.get(q, r2), false);
    BOOST_CHECK_EQUAL(PC.size(), 0U);

    PC.insert(q, r, 3600);
    BOOST_CHECK_EQUAL(PC.size(), 1U);
    BOOST_CHECK_EQUAL(PC.get(q, r2), true);
    BOOST_CHECK_EQUAL(r2.qdomain, r.qdomain);
    BOOST_CHECK_EQUAL(PC.purge("www.powerdns.com$"), 1U);
    BOOST_CHECK_EQUAL(PC.get(q, r2), false);
    BOOST_CHECK_EQUAL(PC.size(), 0U);

    PC.insert(q, r, 3600);
    BOOST_CHECK_EQUAL(PC.size(), 1U);
    BOOST_CHECK_EQUAL(PC.purge("www.powerdns.net"), 0U);
    BOOST_CHECK_EQUAL(PC.get(q, r2), true);
    BOOST_CHECK_EQUAL(r2.qdomain, r.qdomain);
    BOOST_CHECK_EQUAL(PC.size(), 1U);

    BOOST_CHECK_EQUAL(PC.purge("net$"), 0U);
    BOOST_CHECK_EQUAL(PC.get(q, r2), true);
    BOOST_CHECK_EQUAL(r2.qdomain, r.qdomain);
    BOOST_CHECK_EQUAL(PC.size(), 1U);

    BOOST_CHECK_EQUAL(PC.purge("www.powerdns.com$"), 1U);
    BOOST_CHECK_EQUAL(PC.size(), 0U);
  }
  catch(PDNSException& e) {
    cerr<<"Had error in AuthPacketCache: "<<e.reason<<endl;
    throw;
  }
}

BOOST_AUTO_TEST_SUITE_END()
