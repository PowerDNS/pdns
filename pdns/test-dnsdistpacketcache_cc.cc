#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN

#include <boost/test/unit_test.hpp>

#include "ednscookies.hh"
#include "ednsoptions.hh"
#include "ednssubnet.hh"
#include "dnsdist.hh"
#include "iputils.hh"
#include "dnswriter.hh"
#include "dnsdist-cache.hh"
#include "gettime.hh"
#include "packetcache.hh"

BOOST_AUTO_TEST_SUITE(test_dnsdistpacketcache_cc)

BOOST_AUTO_TEST_CASE(test_PacketCacheSimple) {
  const size_t maxEntries = 150000;
  DNSDistPacketCache PC(maxEntries, 86400, 1);
  BOOST_CHECK_EQUAL(PC.getSize(), 0U);
  struct timespec queryTime;
  gettime(&queryTime);  // does not have to be accurate ("realTime") in tests

  size_t counter=0;
  size_t skipped=0;
  ComboAddress remote;
  bool dnssecOK = false;
  const time_t now = time(nullptr);
  try {
    for (counter = 0; counter < 100000; ++counter) {
      DNSName a=DNSName(std::to_string(counter))+DNSName(" hello");
      BOOST_CHECK_EQUAL(DNSName(a.toString()), a);

      PacketBuffer query;
      GenericDNSPacketWriter<PacketBuffer> pwQ(query, a, QType::A, QClass::IN, 0);
      pwQ.getHeader()->rd = 1;

      PacketBuffer response;
      GenericDNSPacketWriter<PacketBuffer> pwR(response, a, QType::A, QClass::IN, 0);
      pwR.getHeader()->rd = 1;
      pwR.getHeader()->ra = 1;
      pwR.getHeader()->qr = 1;
      pwR.getHeader()->id = pwQ.getHeader()->id;
      pwR.startRecord(a, QType::A, 7200, QClass::IN, DNSResourceRecord::ANSWER);
      pwR.xfr32BitInt(0x01020304);
      pwR.commit();

      uint32_t key = 0;
      boost::optional<Netmask> subnet;
      DNSQuestion dq(&a, QType::A, QClass::IN, &remote, &remote, query, false, &queryTime);
      bool found = PC.get(dq, 0, &key, subnet, dnssecOK);
      BOOST_CHECK_EQUAL(found, false);
      BOOST_CHECK(!subnet);

      PC.insert(key, subnet, *(getFlagsFromDNSHeader(dq.getHeader())), dnssecOK, a, QType::A, QClass::IN, response, false, 0, boost::none);

      found = PC.get(dq, pwR.getHeader()->id, &key, subnet, dnssecOK, 0, true);
      if (found == true) {
        BOOST_CHECK_EQUAL(dq.getData().size(), response.size());
        int match = memcmp(dq.getData().data(), response.data(), dq.getData().size());
        BOOST_CHECK_EQUAL(match, 0);
        BOOST_CHECK(!subnet);
      }
      else {
        skipped++;
      }
    }

    BOOST_CHECK_EQUAL(skipped, PC.getInsertCollisions());
    BOOST_CHECK_EQUAL(PC.getSize(), counter - skipped);

    size_t deleted=0;
    size_t delcounter=0;
    for (delcounter=0; delcounter < counter/1000; ++delcounter) {
      DNSName a=DNSName(std::to_string(delcounter))+DNSName(" hello");
      PacketBuffer query;
      GenericDNSPacketWriter<PacketBuffer> pwQ(query, a, QType::A, QClass::IN, 0);
      pwQ.getHeader()->rd = 1;
      uint32_t key = 0;
      boost::optional<Netmask> subnet;
      DNSQuestion dq(&a, QType::A, QClass::IN, &remote, &remote, query, false, &queryTime);
      bool found = PC.get(dq, 0, &key, subnet, dnssecOK);
      if (found == true) {
        auto removed = PC.expungeByName(a);
        BOOST_CHECK_EQUAL(removed, 1U);
        deleted += removed;
      }
    }
    BOOST_CHECK_EQUAL(PC.getSize(), counter - skipped - deleted);

    size_t matches=0;
    size_t expected=counter-skipped-deleted;
    for (; delcounter < counter; ++delcounter) {
      DNSName a(DNSName(std::to_string(delcounter))+DNSName(" hello"));
      PacketBuffer query;
      GenericDNSPacketWriter<PacketBuffer> pwQ(query, a, QType::A, QClass::IN, 0);
      pwQ.getHeader()->rd = 1;
      uint32_t key = 0;
      boost::optional<Netmask> subnet;
      DNSQuestion dq(&a, QType::A, QClass::IN, &remote, &remote, query, false, &queryTime);
      if (PC.get(dq, pwQ.getHeader()->id, &key, subnet, dnssecOK)) {
        matches++;
      }
    }

    /* in the unlikely event that the test took so long that the entries did expire.. */
    auto expired = PC.purgeExpired(0, now);
    BOOST_CHECK_EQUAL(matches + expired, expected);

    auto remaining = PC.getSize();
    auto removed = PC.expungeByName(DNSName(" hello"), QType::ANY, true);
    BOOST_CHECK_EQUAL(PC.getSize(), 0U);
    BOOST_CHECK_EQUAL(removed, remaining);
  }
  catch (const PDNSException& e) {
    cerr<<"Had error: "<<e.reason<<endl;
    throw;
  }
}

BOOST_AUTO_TEST_CASE(test_PacketCacheSharded) {
  const size_t maxEntries = 150000;
  const size_t numberOfShards = 10;
  DNSDistPacketCache PC(maxEntries, 86400, 1, 60, 3600, 60, false, numberOfShards);
  BOOST_CHECK_EQUAL(PC.getSize(), 0U);
  struct timespec queryTime;
  gettime(&queryTime);  // does not have to be accurate ("realTime") in tests

  size_t counter = 0;
  size_t skipped = 0;
  ComboAddress remote;
  bool dnssecOK = false;
  const time_t now = time(nullptr);

  try {
    for (counter = 0; counter < 100000; ++counter) {
      DNSName a(std::to_string(counter) + ".powerdns.com.");

      PacketBuffer query;
      GenericDNSPacketWriter<PacketBuffer> pwQ(query, a, QType::AAAA, QClass::IN, 0);
      pwQ.getHeader()->rd = 1;

      PacketBuffer response;
      GenericDNSPacketWriter<PacketBuffer> pwR(response, a, QType::AAAA, QClass::IN, 0);
      pwR.getHeader()->rd = 1;
      pwR.getHeader()->ra = 1;
      pwR.getHeader()->qr = 1;
      pwR.getHeader()->id = pwQ.getHeader()->id;
      pwR.startRecord(a, QType::AAAA, 7200, QClass::IN, DNSResourceRecord::ANSWER);
      ComboAddress v6("2001:db8::1");
      pwR.xfrIP6(std::string(reinterpret_cast<const char*>(v6.sin6.sin6_addr.s6_addr), 16));
      pwR.xfr32BitInt(0x01020304);
      pwR.commit();

      uint32_t key = 0;
      boost::optional<Netmask> subnet;
      DNSQuestion dq(&a, QType::AAAA, QClass::IN, &remote, &remote, query, false, &queryTime);
      bool found = PC.get(dq, 0, &key, subnet, dnssecOK);
      BOOST_CHECK_EQUAL(found, false);
      BOOST_CHECK(!subnet);

      PC.insert(key, subnet, *(getFlagsFromDNSHeader(dq.getHeader())), dnssecOK, a, QType::AAAA, QClass::IN, response, false, 0, boost::none);

      found = PC.get(dq, pwR.getHeader()->id, &key, subnet, dnssecOK, 0, true);
      if (found == true) {
        BOOST_CHECK_EQUAL(dq.getData().size(), response.size());
        int match = memcmp(dq.getData().data(), response.data(), dq.getData().size());
        BOOST_CHECK_EQUAL(match, 0);
        BOOST_CHECK(!subnet);
      }
      else {
        skipped++;
      }
    }

    BOOST_CHECK_EQUAL(skipped, PC.getInsertCollisions());
    BOOST_CHECK_EQUAL(PC.getSize(), counter - skipped);

    size_t matches = 0;
    for (counter = 0; counter < 100000; ++counter) {
      DNSName a(std::to_string(counter) + ".powerdns.com.");

      PacketBuffer query;
      GenericDNSPacketWriter<PacketBuffer> pwQ(query, a, QType::AAAA, QClass::IN, 0);
      pwQ.getHeader()->rd = 1;
      uint32_t key = 0;
      boost::optional<Netmask> subnet;
      DNSQuestion dq(&a, QType::AAAA, QClass::IN, &remote, &remote, query, false, &queryTime);
      if (PC.get(dq, pwQ.getHeader()->id, &key, subnet, dnssecOK)) {
        matches++;
      }
    }

    BOOST_CHECK_EQUAL(matches, counter - skipped);

    auto remaining = PC.getSize();

    /* no entry should have expired */
    auto expired = PC.purgeExpired(0, now);
    BOOST_CHECK_EQUAL(expired, 0U);

    /* but after the TTL .. let's ask for at most 1k entries */
    auto removed = PC.purgeExpired(1000, now + 7200 + 3600);
    BOOST_CHECK_EQUAL(removed, remaining - 1000U);
    BOOST_CHECK_EQUAL(PC.getSize(), 1000U);

    /* now remove everything */
    removed = PC.purgeExpired(0, now + 7200 + 3600);
    BOOST_CHECK_EQUAL(removed, 1000U);
    BOOST_CHECK_EQUAL(PC.getSize(), 0U);
  }
  catch (const PDNSException& e) {
    cerr<<"Had error: "<<e.reason<<endl;
    throw;
  }
}

BOOST_AUTO_TEST_CASE(test_PacketCacheServFailTTL) {
  const size_t maxEntries = 150000;
  DNSDistPacketCache PC(maxEntries, 86400, 1);
  struct timespec queryTime;
  gettime(&queryTime);  // does not have to be accurate ("realTime") in tests

  ComboAddress remote;
  bool dnssecOK = false;
  try {
    DNSName a = DNSName("servfail");
    BOOST_CHECK_EQUAL(DNSName(a.toString()), a);

    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> pwQ(query, a, QType::A, QClass::IN, 0);
    pwQ.getHeader()->rd = 1;

    PacketBuffer response;
    GenericDNSPacketWriter<PacketBuffer> pwR(response, a, QType::A, QClass::IN, 0);
    pwR.getHeader()->rd = 1;
    pwR.getHeader()->ra = 0;
    pwR.getHeader()->qr = 1;
    pwR.getHeader()->rcode = RCode::ServFail;
    pwR.getHeader()->id = pwQ.getHeader()->id;
    pwR.commit();

    uint32_t key = 0;
    boost::optional<Netmask> subnet;
    DNSQuestion dq(&a, QType::A, QClass::IN, &remote, &remote, query, false, &queryTime);
    bool found = PC.get(dq, 0, &key, subnet, dnssecOK);
    BOOST_CHECK_EQUAL(found, false);
    BOOST_CHECK(!subnet);

    // Insert with failure-TTL of 0 (-> should not enter cache).
    PC.insert(key, subnet, *(getFlagsFromDNSHeader(dq.getHeader())), dnssecOK, a, QType::A, QClass::IN, response, false, RCode::ServFail, boost::optional<uint32_t>(0));
    found = PC.get(dq, pwR.getHeader()->id, &key, subnet, dnssecOK, 0, true);
    BOOST_CHECK_EQUAL(found, false);
    BOOST_CHECK(!subnet);

    // Insert with failure-TTL non-zero (-> should enter cache).
    PC.insert(key, subnet, *(getFlagsFromDNSHeader(dq.getHeader())), dnssecOK, a, QType::A, QClass::IN, response, false, RCode::ServFail, boost::optional<uint32_t>(300));
    found = PC.get(dq, pwR.getHeader()->id, &key, subnet, dnssecOK, 0, true);
    BOOST_CHECK_EQUAL(found, true);
    BOOST_CHECK(!subnet);
  }
  catch(PDNSException& e) {
    cerr<<"Had error: "<<e.reason<<endl;
    throw;
  }
}

BOOST_AUTO_TEST_CASE(test_PacketCacheNoDataTTL) {
  const size_t maxEntries = 150000;
  DNSDistPacketCache PC(maxEntries, /* maxTTL */ 86400, /* minTTL */ 1, /* tempFailureTTL */ 60, /* maxNegativeTTL */ 1);

  struct timespec queryTime;
  gettime(&queryTime);  // does not have to be accurate ("realTime") in tests

  ComboAddress remote;
  bool dnssecOK = false;
  try {
    DNSName name("nodata");
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> pwQ(query, name, QType::A, QClass::IN, 0);
    pwQ.getHeader()->rd = 1;

    PacketBuffer response;
    GenericDNSPacketWriter<PacketBuffer> pwR(response, name, QType::A, QClass::IN, 0);
    pwR.getHeader()->rd = 1;
    pwR.getHeader()->ra = 0;
    pwR.getHeader()->qr = 1;
    pwR.getHeader()->rcode = RCode::NoError;
    pwR.getHeader()->id = pwQ.getHeader()->id;
    pwR.commit();
    pwR.startRecord(name, QType::SOA, 86400, QClass::IN, DNSResourceRecord::AUTHORITY);
    pwR.commit();
    pwR.addOpt(4096, 0, 0);
    pwR.commit();

    uint32_t key = 0;
    boost::optional<Netmask> subnet;
    DNSQuestion dq(&name, QType::A, QClass::IN, &remote, &remote, query, false, &queryTime);
    bool found = PC.get(dq, 0, &key, subnet, dnssecOK);
    BOOST_CHECK_EQUAL(found, false);
    BOOST_CHECK(!subnet);

    PC.insert(key, subnet, *(getFlagsFromDNSHeader(dq.getHeader())), dnssecOK, name, QType::A, QClass::IN, response, false, RCode::NoError, boost::none);
    found = PC.get(dq, pwR.getHeader()->id, &key, subnet, dnssecOK, 0, true);
    BOOST_CHECK_EQUAL(found, true);
    BOOST_CHECK(!subnet);

    sleep(2);
    /* it should have expired by now */
    found = PC.get(dq, pwR.getHeader()->id, &key, subnet, dnssecOK, 0, true);
    BOOST_CHECK_EQUAL(found, false);
    BOOST_CHECK(!subnet);
  }
  catch(const PDNSException& e) {
    cerr<<"Had error: "<<e.reason<<endl;
    throw;
  }
}

BOOST_AUTO_TEST_CASE(test_PacketCacheNXDomainTTL) {
  const size_t maxEntries = 150000;
  DNSDistPacketCache PC(maxEntries, /* maxTTL */ 86400, /* minTTL */ 1, /* tempFailureTTL */ 60, /* maxNegativeTTL */ 1);

  struct timespec queryTime;
  gettime(&queryTime);  // does not have to be accurate ("realTime") in tests

  ComboAddress remote;
  bool dnssecOK = false;
  try {
    DNSName name("nxdomain");
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> pwQ(query, name, QType::A, QClass::IN, 0);
    pwQ.getHeader()->rd = 1;

    PacketBuffer response;
    GenericDNSPacketWriter<PacketBuffer> pwR(response, name, QType::A, QClass::IN, 0);
    pwR.getHeader()->rd = 1;
    pwR.getHeader()->ra = 0;
    pwR.getHeader()->qr = 1;
    pwR.getHeader()->rcode = RCode::NXDomain;
    pwR.getHeader()->id = pwQ.getHeader()->id;
    pwR.commit();
    pwR.startRecord(name, QType::SOA, 86400, QClass::IN, DNSResourceRecord::AUTHORITY);
    pwR.commit();
    pwR.addOpt(4096, 0, 0);
    pwR.commit();

    uint32_t key = 0;
    boost::optional<Netmask> subnet;
    DNSQuestion dq(&name, QType::A, QClass::IN, &remote, &remote, query, false, &queryTime);
    bool found = PC.get(dq, 0, &key, subnet, dnssecOK);
    BOOST_CHECK_EQUAL(found, false);
    BOOST_CHECK(!subnet);

    PC.insert(key, subnet, *(getFlagsFromDNSHeader(dq.getHeader())), dnssecOK, name, QType::A, QClass::IN, response, false, RCode::NXDomain, boost::none);
    found = PC.get(dq, pwR.getHeader()->id, &key, subnet, dnssecOK, 0, true);
    BOOST_CHECK_EQUAL(found, true);
    BOOST_CHECK(!subnet);

    sleep(2);
    /* it should have expired by now */
    found = PC.get(dq, pwR.getHeader()->id, &key, subnet, dnssecOK, 0, true);
    BOOST_CHECK_EQUAL(found, false);
    BOOST_CHECK(!subnet);
  }
  catch(const PDNSException& e) {
    cerr<<"Had error: "<<e.reason<<endl;
    throw;
  }
}

static DNSDistPacketCache g_PC(500000);

static void threadMangler(unsigned int offset)
{
  struct timespec queryTime;
  gettime(&queryTime);  // does not have to be accurate ("realTime") in tests
  try {
    ComboAddress remote;
    bool dnssecOK = false;
    for(unsigned int counter=0; counter < 100000; ++counter) {
      DNSName a=DNSName("hello ")+DNSName(std::to_string(counter+offset));
      PacketBuffer query;
      GenericDNSPacketWriter<PacketBuffer> pwQ(query, a, QType::A, QClass::IN, 0);
      pwQ.getHeader()->rd = 1;

      PacketBuffer response;
      GenericDNSPacketWriter<PacketBuffer> pwR(response, a, QType::A, QClass::IN, 0);
      pwR.getHeader()->rd = 1;
      pwR.getHeader()->ra = 1;
      pwR.getHeader()->qr = 1;
      pwR.getHeader()->id = pwQ.getHeader()->id;
      pwR.startRecord(a, QType::A, 3600, QClass::IN, DNSResourceRecord::ANSWER);
      pwR.xfr32BitInt(0x01020304);
      pwR.commit();

      uint32_t key = 0;
      boost::optional<Netmask> subnet;
      DNSQuestion dq(&a, QType::A, QClass::IN, &remote, &remote, query, false, &queryTime);
      g_PC.get(dq, 0, &key, subnet, dnssecOK);

      g_PC.insert(key, subnet, *(getFlagsFromDNSHeader(dq.getHeader())), dnssecOK, a, QType::A, QClass::IN, response, false, 0, boost::none);
    }
  }
  catch(PDNSException& e) {
    cerr<<"Had error: "<<e.reason<<endl;
    throw;
  }
}

AtomicCounter g_missing;

static void threadReader(unsigned int offset)
{
  bool dnssecOK = false;
  struct timespec queryTime;
  gettime(&queryTime);  // does not have to be accurate ("realTime") in tests
  try
  {
    ComboAddress remote;
    for(unsigned int counter=0; counter < 100000; ++counter) {
      DNSName a=DNSName("hello ")+DNSName(std::to_string(counter+offset));
      PacketBuffer query;
      GenericDNSPacketWriter<PacketBuffer> pwQ(query, a, QType::A, QClass::IN, 0);
      pwQ.getHeader()->rd = 1;

      uint32_t key = 0;
      boost::optional<Netmask> subnet;
      DNSQuestion dq(&a, QType::A, QClass::IN, &remote, &remote, query, false, &queryTime);
      bool found = g_PC.get(dq, 0, &key, subnet, dnssecOK);
      if (!found) {
	g_missing++;
      }
    }
  }
  catch(PDNSException& e) {
    cerr<<"Had error in threadReader: "<<e.reason<<endl;
    throw;
  }
}

BOOST_AUTO_TEST_CASE(test_PacketCacheThreaded) {
  try {
    std::vector<std::thread> threads;
    for (int i = 0; i < 4; ++i) {
      threads.push_back(std::thread(threadMangler, i*1000000UL));
    }

    for (auto& t : threads) {
      t.join();
    }

    threads.clear();

    BOOST_CHECK_EQUAL(g_PC.getSize() + g_PC.getDeferredInserts() + g_PC.getInsertCollisions(), 400000U);
    BOOST_CHECK_SMALL(1.0*g_PC.getInsertCollisions(), 10000.0);

    for (int i = 0; i < 4; ++i) {
      threads.push_back(std::thread(threadReader, i*1000000UL));
    }

    for (auto& t : threads) {
      t.join();
    }

    BOOST_CHECK((g_PC.getDeferredInserts() + g_PC.getDeferredLookups() + g_PC.getInsertCollisions()) >= g_missing);
  }
  catch(PDNSException& e) {
    cerr<<"Had error: "<<e.reason<<endl;
    throw;
  }

}

BOOST_AUTO_TEST_CASE(test_PCCollision) {
  const size_t maxEntries = 150000;
  DNSDistPacketCache PC(maxEntries, 86400, 1, 60, 3600, 60, false, 1, true, true);
  BOOST_CHECK_EQUAL(PC.getSize(), 0U);

  DNSName qname("www.powerdns.com.");
  uint16_t qtype = QType::AAAA;
  uint16_t qid = 0x42;
  uint32_t key;
  uint32_t secondKey;
  boost::optional<Netmask> subnetOut;
  bool dnssecOK = false;

  /* lookup for a query with a first ECS value,
     insert a corresponding response */
  {
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> pwQ(query, qname, qtype, QClass::IN, 0);
    pwQ.getHeader()->rd = 1;
    pwQ.getHeader()->id = qid;
    GenericDNSPacketWriter<PacketBuffer>::optvect_t ednsOptions;
    EDNSSubnetOpts opt;
    opt.source = Netmask("10.0.59.220/32");
    ednsOptions.push_back(std::make_pair(EDNSOptionCode::ECS, makeEDNSSubnetOptsString(opt)));
    pwQ.addOpt(512, 0, 0, ednsOptions);
    pwQ.commit();

    ComboAddress remote("192.0.2.1");
    struct timespec queryTime;
    gettime(&queryTime);
    DNSQuestion dq(&qname, QType::AAAA, QClass::IN, &remote, &remote, query, false, &queryTime);
    bool found = PC.get(dq, 0, &key, subnetOut, dnssecOK);
    BOOST_CHECK_EQUAL(found, false);
    BOOST_REQUIRE(subnetOut);
    BOOST_CHECK_EQUAL(subnetOut->toString(), opt.source.toString());

    PacketBuffer response;
    GenericDNSPacketWriter<PacketBuffer> pwR(response, qname, qtype, QClass::IN, 0);
    pwR.getHeader()->rd = 1;
    pwR.getHeader()->id = qid;
    pwR.startRecord(qname, qtype, 100, QClass::IN, DNSResourceRecord::ANSWER);
    ComboAddress v6("::1");
    pwR.xfrCAWithoutPort(6, v6);
    pwR.commit();
    pwR.addOpt(512, 0, 0, ednsOptions);
    pwR.commit();

    PC.insert(key, subnetOut, *(getFlagsFromDNSHeader(pwR.getHeader())), dnssecOK, qname, qtype, QClass::IN, response, false, RCode::NoError, boost::none);
    BOOST_CHECK_EQUAL(PC.getSize(), 1U);

    found = PC.get(dq, 0, &key, subnetOut, dnssecOK);
    BOOST_CHECK_EQUAL(found, true);
    BOOST_REQUIRE(subnetOut);
    BOOST_CHECK_EQUAL(subnetOut->toString(), opt.source.toString());
  }

  /* now lookup for the same query with a different ECS value,
     we should get the same key (collision) but no match */
  {
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> pwQ(query, qname, qtype, QClass::IN, 0);
    pwQ.getHeader()->rd = 1;
    pwQ.getHeader()->id = qid;
    GenericDNSPacketWriter<PacketBuffer>::optvect_t ednsOptions;
    EDNSSubnetOpts opt;
    opt.source = Netmask("10.0.167.48/32");
    ednsOptions.push_back(std::make_pair(EDNSOptionCode::ECS, makeEDNSSubnetOptsString(opt)));
    pwQ.addOpt(512, 0, 0, ednsOptions);
    pwQ.commit();

    ComboAddress remote("192.0.2.1");
    struct timespec queryTime;
    gettime(&queryTime);
    DNSQuestion dq(&qname, QType::AAAA, QClass::IN, &remote, &remote, query, false, &queryTime);
    bool found = PC.get(dq, 0, &secondKey, subnetOut, dnssecOK);
    BOOST_CHECK_EQUAL(found, false);
    BOOST_CHECK_EQUAL(secondKey, key);
    BOOST_REQUIRE(subnetOut);
    BOOST_CHECK_EQUAL(subnetOut->toString(), opt.source.toString());
    BOOST_CHECK_EQUAL(PC.getLookupCollisions(), 1U);
  }

#if 0
  /* to be able to compute a new collision if the packet cache hashing code is updated */
  {
    DNSDistPacketCache pc(10000);
    GenericDNSPacketWriter<PacketBuffer>::optvect_t ednsOptions;
    EDNSSubnetOpts opt;
    std::map<uint32_t, Netmask> colMap;
    size_t collisions = 0;
    size_t total = 0;
    //qname = DNSName("collision-with-ecs-parsing.cache.tests.powerdns.com.");

    for (size_t idxA = 0; idxA < 256; idxA++) {
      for (size_t idxB = 0; idxB < 256; idxB++) {
        for (size_t idxC = 0; idxC < 256; idxC++) {
          PacketBuffer secondQuery;
          GenericDNSPacketWriter<PacketBuffer> pwFQ(secondQuery, qname, QType::AAAA, QClass::IN, 0);
          pwFQ.getHeader()->rd = 1;
          pwFQ.getHeader()->qr = false;
          pwFQ.getHeader()->id = 0x42;
          opt.source = Netmask("10." + std::to_string(idxA) + "." + std::to_string(idxB) + "." + std::to_string(idxC) + "/32");
          ednsOptions.clear();
          ednsOptions.push_back(std::make_pair(EDNSOptionCode::ECS, makeEDNSSubnetOptsString(opt)));
          pwFQ.addOpt(512, 0, 0, ednsOptions);
          pwFQ.commit();
          secondKey = pc.getKey(qname.toDNSString(), qname.wirelength(), secondQuery, false);
          auto pair = colMap.insert(std::make_pair(secondKey, opt.source));
          total++;
          if (!pair.second) {
            collisions++;
            cerr<<"Collision between "<<colMap[secondKey].toString()<<" and "<<opt.source.toString()<<" for key "<<secondKey<<endl;
            goto done;
          }
        }
      }
    }
  done:
    cerr<<"collisions: "<<collisions<<endl;
    cerr<<"total: "<<total<<endl;
  }
#endif
}

BOOST_AUTO_TEST_CASE(test_PCDNSSECCollision) {
  const size_t maxEntries = 150000;
  DNSDistPacketCache PC(maxEntries, 86400, 1, 60, 3600, 60, false, 1, true, true);
  BOOST_CHECK_EQUAL(PC.getSize(), 0U);

  DNSName qname("www.powerdns.com.");
  uint16_t qtype = QType::AAAA;
  uint16_t qid = 0x42;
  uint32_t key;
  boost::optional<Netmask> subnetOut;

  /* lookup for a query with DNSSEC OK,
     insert a corresponding response with DO set,
     check that it doesn't match without DO, but does with it */
  {
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> pwQ(query, qname, qtype, QClass::IN, 0);
    pwQ.getHeader()->rd = 1;
    pwQ.getHeader()->id = qid;
    pwQ.addOpt(512, 0, EDNS_HEADER_FLAG_DO);
    pwQ.commit();

    ComboAddress remote("192.0.2.1");
    struct timespec queryTime;
    gettime(&queryTime);
    DNSQuestion dq(&qname, QType::AAAA, QClass::IN, &remote, &remote, query, false, &queryTime);
    bool found = PC.get(dq, 0, &key, subnetOut, true);
    BOOST_CHECK_EQUAL(found, false);

    PacketBuffer response;
    GenericDNSPacketWriter<PacketBuffer> pwR(response, qname, qtype, QClass::IN, 0);
    pwR.getHeader()->rd = 1;
    pwR.getHeader()->id = qid;
    pwR.startRecord(qname, qtype, 100, QClass::IN, DNSResourceRecord::ANSWER);
    ComboAddress v6("::1");
    pwR.xfrCAWithoutPort(6, v6);
    pwR.commit();
    pwR.addOpt(512, 0, EDNS_HEADER_FLAG_DO);
    pwR.commit();

    PC.insert(key, subnetOut, *(getFlagsFromDNSHeader(pwR.getHeader())), /* DNSSEC OK is set */ true, qname, qtype, QClass::IN, response, false, RCode::NoError, boost::none);
    BOOST_CHECK_EQUAL(PC.getSize(), 1U);

    found = PC.get(dq, 0, &key, subnetOut, false);
    BOOST_CHECK_EQUAL(found, false);

    found = PC.get(dq, 0, &key, subnetOut, true);
    BOOST_CHECK_EQUAL(found, true);
  }

}

BOOST_AUTO_TEST_SUITE_END()
