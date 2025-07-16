#ifndef BOOST_TEST_DYN_LINK
#define BOOST_TEST_DYN_LINK
#endif

#define BOOST_TEST_NO_MAIN

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <boost/test/unit_test.hpp>
#include "iputils.hh"
#include "nameserver.hh"
#include "statbag.hh"
#include "auth-packetcache.hh"
#include "auth-querycache.hh"
#ifdef PDNS_AUTH
#include "auth-zonecache.hh"
#endif
#include "arguments.hh"
#include <utility>
#include <thread>

extern StatBag S;

BOOST_AUTO_TEST_SUITE(test_packetcache_cc)

BOOST_AUTO_TEST_CASE(test_AuthQueryCacheSimple) {
  AuthQueryCache QC;
  QC.setMaxEntries(1000000);

  vector<DNSZoneRecord> records;

  BOOST_CHECK_EQUAL(QC.size(), 0U);
  QC.insert(DNSName("hello"), QType(QType::A), vector<DNSZoneRecord>(records), 3600, 1);
  BOOST_CHECK_EQUAL(QC.size(), 1U);
  BOOST_CHECK_EQUAL(QC.purge(), 1U);
  BOOST_CHECK_EQUAL(QC.size(), 0U);

  uint64_t counter=0;
  try {
    for(counter = 0; counter < 100000; ++counter) {
      DNSName a=DNSName("hello ")+DNSName(std::to_string(counter));
      BOOST_CHECK_EQUAL(DNSName(a.toString()), a);

      QC.insert(a, QType(QType::A), vector<DNSZoneRecord>(records), 3600, 1);
      if(!QC.purge(a.toString()))
        BOOST_FAIL("Could not remove entry we just added to the query cache!");
      QC.insert(a, QType(QType::A), vector<DNSZoneRecord>(records), 3600, 1);
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

static void threadQCMangler(unsigned int offset)
try
{
  vector<DNSZoneRecord> records;
  for(unsigned int counter=0; counter < 100000; ++counter)
    g_QC->insert(DNSName("hello ")+DNSName(std::to_string(counter+offset)), QType(QType::A), vector<DNSZoneRecord>(records), 3600, 1);
}
 catch(PDNSException& e) {
   cerr<<"Had error: "<<e.reason<<endl;
   throw;
 }

static void threadQCReader(unsigned int offset)
try
{
  vector<DNSZoneRecord> entry;
  for(unsigned int counter=0; counter < 100000; ++counter)
    if(!g_QC->getEntry(DNSName("hello ")+DNSName(std::to_string(counter+offset)), QType(QType::A), entry, 1)) {
      g_QCmissing++;
    }
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
    std::vector<std::thread> manglers;
    for (int i=0; i < 4; ++i) {
      manglers.push_back(std::thread(threadQCMangler, i*1000000UL));
    }

    for (auto& t : manglers) {
      t.join();
    }
    manglers.clear();

    BOOST_CHECK_EQUAL(QC.size() + S.read("deferred-cache-inserts"), 400000U);
    BOOST_CHECK_SMALL(1.0*S.read("deferred-cache-inserts"), 10000.0);

    std::vector<std::thread> readers;
    for (int i=0; i < 4; ++i) {
      readers.push_back(std::thread(threadQCReader, i*1000000UL));
    }

    for (auto& t : readers) {
      t.join();
    }
    readers.clear();

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

static void threadPCMangler(unsigned int offset)
try
{
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
    g_PC->insert(q, r, maxTTL, "");
  }
}
 catch(PDNSException& e) {
   cerr<<"Had error: "<<e.reason<<endl;
   throw;
 }

static void threadPCReader(unsigned int offset)
try
{
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
    std::vector<std::thread> manglers;
    for (int i=0; i < 4; ++i) {
      manglers.push_back(std::thread(threadPCMangler, i*1000000UL));
    }

    for (auto& t : manglers) {
      t.join();
    }
    manglers.clear();

    BOOST_CHECK_EQUAL(PC.size() + S.read("deferred-packetcache-inserts"), 400000UL);
    BOOST_CHECK_EQUAL(S.read("deferred-packetcache-lookup"), 0UL);
    BOOST_CHECK_SMALL(1.0*S.read("deferred-packetcache-inserts"), 10000.0);

    std::vector<std::thread> readers;
    for (int i=0; i < 4; ++i) {
      readers.push_back(std::thread(threadPCReader, i*1000000UL));
    }

    for (auto& t : readers) {
      t.join();
    }
    readers.clear();

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
static void cacheCleaner()
try
{
  while(!g_stopCleaning) {
    g_QC->cleanup();
  }
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
      QC.insert(DNSName("hello ")+DNSName(std::to_string(counter)), QType(QType::A), vector<DNSZoneRecord>(records), 1, 1);
    }

    sleep(1);

    g_QC=&QC;
    std::vector<std::thread> readers;
    for (int i=0; i < 4; ++i) {
      if (i < 3) {
        readers.push_back(std::thread(threadQCReader, i*1000000UL));
      }
      else {
        readers.push_back(std::thread(cacheCleaner));
      }
    }

    for (int i = 0; i < 3 ; ++i) {
      readers.at(i).join();
    }

    g_stopCleaning=true;
    readers.at(3).join();

    readers.clear();
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
      ecsOpts.setSource(Netmask(ComboAddress("192.0.2.1"), 32));
      opts.emplace_back(EDNSOptionCode::ECS, ecsOpts.makeOptString());
      DNSPacketWriter pw(pak, DNSName("www.powerdns.com"), QType::A);
      pw.addOpt(512, 0, 0, opts);
      pw.commit();
      ecs1.parse((char*)&pak[0], pak.size());
      pak.clear();
      opts.clear();
    }

    {
      DNSPacketWriter pw(pak, DNSName("www.powerdns.com"), QType::A);
      ecsOpts.setSource(Netmask(ComboAddress("192.0.2.2"), 32));
      opts.emplace_back(EDNSOptionCode::ECS, ecsOpts.makeOptString());
      pw.addOpt(512, 0, 0, opts);
      pw.commit();
      ecs2.parse((char*)&pak[0], pak.size());
      pak.clear();
      opts.clear();
    }

    {
      DNSPacketWriter pw(pak, DNSName("www.powerdns.com"), QType::A);
      ecsOpts.setSource(Netmask(ComboAddress("192.0.2.3"), 16));
      opts.emplace_back(EDNSOptionCode::ECS, ecsOpts.makeOptString());
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

    PC.insert(q, r, 3600, "");
    BOOST_CHECK_EQUAL(PC.size(), 1U);

    BOOST_CHECK_EQUAL(PC.get(q, r2), true);
    BOOST_CHECK_EQUAL(r2.qdomain, r.qdomain);

    /* different QID, still should match */
    BOOST_CHECK_EQUAL(PC.get(differentIDQ, r2), true);
    BOOST_CHECK_EQUAL(r2.qdomain, r.qdomain);

    /* with EDNS, should not match */
    BOOST_CHECK_EQUAL(PC.get(ednsQ, r2), false);
    /* inserting the EDNS-enabled one too */
    PC.insert(ednsQ, r, 3600, "");
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
    PC.insert(ecs1, r, 3600, "");
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

    PC.insert(q, r, 3600, "");
    BOOST_CHECK_EQUAL(PC.size(), 1U);
    BOOST_CHECK_EQUAL(PC.get(q, r2), true);
    BOOST_CHECK_EQUAL(r2.qdomain, r.qdomain);
    BOOST_CHECK_EQUAL(PC.purge("com$"), 1U);
    BOOST_CHECK_EQUAL(PC.get(q, r2), false);
    BOOST_CHECK_EQUAL(PC.size(), 0U);

    PC.insert(q, r, 3600, "");
    BOOST_CHECK_EQUAL(PC.size(), 1U);
    BOOST_CHECK_EQUAL(PC.get(q, r2), true);
    BOOST_CHECK_EQUAL(r2.qdomain, r.qdomain);
    BOOST_CHECK_EQUAL(PC.purge("powerdns.com$"), 1U);
    BOOST_CHECK_EQUAL(PC.get(q, r2), false);
    BOOST_CHECK_EQUAL(PC.size(), 0U);

    PC.insert(q, r, 3600, "");
    BOOST_CHECK_EQUAL(PC.size(), 1U);
    BOOST_CHECK_EQUAL(PC.get(q, r2), true);
    BOOST_CHECK_EQUAL(r2.qdomain, r.qdomain);
    BOOST_CHECK_EQUAL(PC.purge("www.powerdns.com$"), 1U);
    BOOST_CHECK_EQUAL(PC.get(q, r2), false);
    BOOST_CHECK_EQUAL(PC.size(), 0U);

    PC.insert(q, r, 3600, "");
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

static void feedPacketCache(AuthPacketCache& PC, uint32_t bits, const std::string& view) // NOLINT(readability-identifier-length)
{
  for (unsigned int counter = 0; counter < 128; ++counter) {
    std::vector<uint8_t> storage;
    DNSName qname = DNSName("network" + std::to_string(counter));
    DNSPacketWriter qwriter(storage, qname, QType::A);
    DNSPacket query(true);
    query.parse(reinterpret_cast<char*>(storage.data()), storage.size()); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast): can't static_cast because of sign difference
    storage.clear();
    DNSPacketWriter rwriter(storage, qname, QType::A);
    rwriter.startRecord(qname, QType::A, 3600, QClass::IN, DNSResourceRecord::ANSWER);
    rwriter.xfrIP(htonl((counter << 24) | bits));
    rwriter.commit();
    DNSPacket response(false);
    response.parse(reinterpret_cast<char*>(storage.data()), storage.size()); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast): can't static_cast because of sign difference
    // magic copied from threadPCMangler() above
    query.setHash(PacketCache::canHashPacket(query.getString()));
    PC.insert(query, response, 2600, view);
  }
}

static void slurpPacketCache(AuthPacketCache& PC, const std::string& bits, const std::string& view) // NOLINT(readability-identifier-length)
{
  for (unsigned int counter = 0; counter < 128; ++counter) {
    std::vector<uint8_t> storage;
    DNSName qname = DNSName("network" + std::to_string(counter));
    DNSPacketWriter qwriter(storage, qname, QType::A);
    DNSPacket query(true);
    query.parse(reinterpret_cast<char*>(storage.data()), storage.size()); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast): can't static_cast because of sign difference

    DNSPacket response(false);
    bool hit = PC.get(query, response, view);
    BOOST_CHECK_EQUAL(hit, true);
    if (!hit) {
      continue;
    }
    BOOST_CHECK_EQUAL(response.qdomain, query.qdomain);
    const std::string& wiresponse = response.getString();
    MOADNSParser parser(false, wiresponse.c_str(), wiresponse.size());
    BOOST_REQUIRE_EQUAL(parser.d_answers.size(), 1U);
    const auto& record = parser.d_answers.at(0);
    BOOST_REQUIRE_EQUAL(record.d_type, QType::A);
    BOOST_REQUIRE_EQUAL(record.d_class, QClass::IN);
    auto content = getRR<ARecordContent>(record);
    BOOST_REQUIRE(content);
    BOOST_REQUIRE_EQUAL(content->getCA().toString(), std::to_string(counter) + bits);
  }
}

BOOST_AUTO_TEST_CASE(test_AuthPacketCacheNetmasks) {
  try {
    ::arg().setSwitch("no-shuffle","Set this to prevent random shuffling of answers - for regression testing")="off";

    AuthPacketCache PC; // NOLINT(readability-identifier-length) 
    PC.setMaxEntries(1000000);
    PC.setTTL(0xc0ffee); // cache works better when programmer is cafeinated and doesn't forget to enable it

    std::string view1{"view1"};
    std::string view2{"view2"};

    // Set up a few packets with no view.
    feedPacketCache(PC, 0x00010203, "");
    BOOST_REQUIRE_EQUAL(PC.size(), 128 * 1);

    // Set up a few packets with a view and different A result.
    feedPacketCache(PC, 0x00020406, view1);
    BOOST_REQUIRE_EQUAL(PC.size(), 128 * 2);

    // Set up a few packets with yet another view and yet another different A result.
    feedPacketCache(PC, 0x00030609, view2);
    BOOST_REQUIRE_EQUAL(PC.size(), 128 * 3);

    // Now check that we are getting cache hits for all the packets we've added,
    // with the correct answers
    slurpPacketCache(PC, ".1.2.3", "");
    slurpPacketCache(PC, ".2.4.6", view1);
    slurpPacketCache(PC, ".3.6.9", view2);
  }
  catch(PDNSException& e) {
    cerr<<"Had error in AuthPacketCache: "<<e.reason<<endl;
    throw;
  }
}

#ifdef PDNS_AUTH // [
// Combined packet cache and zone cache test to exercize views

static DNSPacket buildQuery(const DNSName& qname)
{
  std::vector<uint8_t> storage;
  DNSPacketWriter qwriter(storage, qname, QType::A);
  DNSPacket query(true);
  query.parse(reinterpret_cast<char*>(storage.data()), storage.size()); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast): can't static_cast because of sign difference
  storage.clear();
  // magic copied from threadPCMangler() above
  query.setHash(PacketCache::canHashPacket(query.getString()));
  return query;
}

static void feedPacketCache2(AuthPacketCache& PC, const std::string& view, uint32_t ipAddress, const DNSName& qname) // NOLINT(readability-identifier-length)
{
  DNSPacket query = buildQuery(qname);

  std::vector<uint8_t> storage;
  DNSPacketWriter rwriter(storage, qname, QType::A);
  rwriter.startRecord(qname, QType::A, 3600, QClass::IN, DNSResourceRecord::ANSWER);
  rwriter.xfrIP(htonl(ipAddress));
  rwriter.commit();
  DNSPacket response(false);
  response.parse(reinterpret_cast<char*>(storage.data()), storage.size()); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast): can't static_cast because of sign difference

  PC.insert(query, response, 2600, view);
}

static bool queryPacketCache2(AuthPacketCache& PC, AuthZoneCache& ZC, ComboAddress from, const DNSName& qname, const Netmask& expectedMask, const std::string& expectedView, const std::string& expectedAddress) // NOLINT(readability-identifier-length)
{
  DNSPacket query = buildQuery(qname);
  DNSPacket response(false);

  Netmask netmask(from);
  std::string view = ZC.getViewFromNetwork(&netmask);
  BOOST_REQUIRE(netmask == expectedMask);
  BOOST_REQUIRE(view == expectedView);

  bool hit = PC.get(query, response, view);
  if (hit) {
    BOOST_CHECK_EQUAL(response.qdomain, query.qdomain);
    const std::string& wiresponse = response.getString();
    MOADNSParser parser(false, wiresponse.c_str(), wiresponse.size());
    BOOST_REQUIRE_EQUAL(parser.d_answers.size(), 1U);
    const auto& record = parser.d_answers.at(0);
    BOOST_REQUIRE_EQUAL(record.d_type, QType::A);
    BOOST_REQUIRE_EQUAL(record.d_class, QClass::IN);
    auto content = getRR<ARecordContent>(record);
    BOOST_REQUIRE(content);
    BOOST_REQUIRE_EQUAL(content->getCA().toString(), expectedAddress);
  }
  return hit;
}

BOOST_AUTO_TEST_CASE(test_AuthViews)
{
  // Setup Zone Cache

  AuthZoneCache ZC; // NOLINT(readability-identifier-length) 
  ZC.setRefreshInterval(3600);

  // Declare a few zones
  ZoneName foo("example.com..foo");
  ZoneName bar("example.com..bar");
  ZC.add(foo, static_cast<domainid_t>('F'));
  ZC.add(bar, static_cast<domainid_t>('B'));

  // Declare a few networks
  std::string view1{"view1"};
  std::string view2{"view2"};
  Netmask outerMask("192.0.2.0/24");
  Netmask innerMask("192.0.2.0/25");
  ZC.updateNetwork(outerMask, view1);
  ZC.updateNetwork(innerMask, view2);

  // Declare a few views
  ZC.addToView(view1, foo);
  ZC.addToView(view2, bar);

  // Setup Packet Cache

  AuthPacketCache PC; // NOLINT(readability-identifier-length) 
  PC.setMaxEntries(1000000);
  PC.setTTL(0xc0ffee); // cache works better when programmer is cafeinated and doesn't forget to enable it

  // Cache answer for query in view2
  DNSName qname("example.com");
  feedPacketCache2(PC, view2, 0x02020202, qname);
  BOOST_CHECK_EQUAL(PC.size(), 1);

  // Check that requesting from view1 causes a cache miss
  BOOST_CHECK_EQUAL(queryPacketCache2(PC, ZC, ComboAddress("192.0.2.128"), qname, outerMask, view1, "1.1.1.1"), false);

  // Check that requesting from view2 causes a cache hit
  BOOST_CHECK_EQUAL(queryPacketCache2(PC, ZC, ComboAddress("192.0.2.1"), qname, innerMask, view2, "2.2.2.2"), true);

  // Cache answer for query in view1
  feedPacketCache2(PC, view1, 0x01010101, qname);
  BOOST_CHECK_EQUAL(PC.size(), 2);

  // Check that requesting from view1 causes a cache hit with the right data
  BOOST_CHECK_EQUAL(queryPacketCache2(PC, ZC, ComboAddress("192.0.2.128"), qname, outerMask, view1, "1.1.1.1"), true);

  // Check that requesting from view2 causes a cache hit with the right data
  BOOST_CHECK_EQUAL(queryPacketCache2(PC, ZC, ComboAddress("192.0.2.1"), qname, innerMask, view2, "2.2.2.2"), true);

  // Purge view2
  std::string purgeName = qname.toString();
  purgeName.append("$");
  BOOST_CHECK_EQUAL(PC.purge(view2, purgeName), 1);
  BOOST_CHECK_EQUAL(PC.size(), 1);

  // Check that requesting from view2 causes a cache miss
  BOOST_CHECK_EQUAL(queryPacketCache2(PC, ZC, ComboAddress("192.0.2.1"), qname, innerMask, view2, "2.2.2.2"), false);

  // Check that requesting from view1 causes a cache hit with the right data
  BOOST_CHECK_EQUAL(queryPacketCache2(PC, ZC, ComboAddress("192.0.2.128"), qname, outerMask, view1, "1.1.1.1"), true);

  // Purge view1
  purgeName = qname.toString();
  purgeName.append("$");
  BOOST_CHECK_EQUAL(PC.purge(view1, purgeName), 1);
  BOOST_CHECK_EQUAL(PC.size(), 0);

  // Check that requesting from view1 causes a cache miss
  BOOST_CHECK_EQUAL(queryPacketCache2(PC, ZC, ComboAddress("192.0.2.128"), qname, outerMask, view1, "1.1.1.1"), false);

  // Cache answers for view1 and view2 again
  feedPacketCache2(PC, view1, 0x01010101, qname);
  feedPacketCache2(PC, view2, 0x02020202, qname);
  BOOST_CHECK_EQUAL(PC.size(), 2);

  // Purge all views
  BOOST_CHECK_EQUAL(PC.purgeExact(qname), 2);
  BOOST_CHECK_EQUAL(PC.size(), 0);

  // Check that requesting from view1 causes a cache miss
  BOOST_CHECK_EQUAL(queryPacketCache2(PC, ZC, ComboAddress("192.0.2.128"), qname, outerMask, view1, "1.1.1.1"), false);

  // Check that requesting from view2 causes a cache miss
  BOOST_CHECK_EQUAL(queryPacketCache2(PC, ZC, ComboAddress("192.0.2.1"), qname, innerMask, view2, "2.2.2.2"), false);

  // Cache answers for view1 and view2 again
  feedPacketCache2(PC, view1, 0x01010101, qname);
  feedPacketCache2(PC, view2, 0x02020202, qname);
  BOOST_CHECK_EQUAL(PC.size(), 2);

  // Purge view1
  BOOST_CHECK_EQUAL(PC.purgeView(view1), 1);
  BOOST_CHECK_EQUAL(PC.size(), 1);

  // Purge view2
  BOOST_CHECK_EQUAL(PC.purgeView(view2), 1);
  BOOST_CHECK_EQUAL(PC.size(), 0);
}
#endif // ] PDNS_AUTH

BOOST_AUTO_TEST_SUITE_END()
