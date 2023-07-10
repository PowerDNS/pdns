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

static bool receivedOverUDP = true;

BOOST_AUTO_TEST_CASE(test_PacketCacheSimple) {
  const size_t maxEntries = 150000;
  DNSDistPacketCache PC(maxEntries, 86400, 1);
  BOOST_CHECK_EQUAL(PC.getSize(), 0U);

  size_t counter = 0;
  size_t skipped = 0;
  bool dnssecOK = false;
  const time_t now = time(nullptr);
  InternalQueryState ids;
  ids.qtype = QType::A;
  ids.qclass = QClass::IN;
  ids.protocol = dnsdist::Protocol::DoUDP;

  try {
    for (counter = 0; counter < 100000; ++counter) {
      auto a = DNSName(std::to_string(counter))+DNSName(" hello");
      ids.qname = a;

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
      DNSQuestion dq(ids, query);
      bool found = PC.get(dq, 0, &key, subnet, dnssecOK, receivedOverUDP);
      BOOST_CHECK_EQUAL(found, false);
      BOOST_CHECK(!subnet);

      PC.insert(key, subnet, *(getFlagsFromDNSHeader(dq.getHeader())), dnssecOK, a, QType::A, QClass::IN, response, receivedOverUDP, 0, boost::none);

      found = PC.get(dq, pwR.getHeader()->id, &key, subnet, dnssecOK, receivedOverUDP, 0, true);
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
      ids.qname = DNSName(std::to_string(delcounter))+DNSName(" hello");
      PacketBuffer query;
      GenericDNSPacketWriter<PacketBuffer> pwQ(query, ids.qname, QType::A, QClass::IN, 0);
      pwQ.getHeader()->rd = 1;
      uint32_t key = 0;
      boost::optional<Netmask> subnet;
      DNSQuestion dq(ids, query);
      bool found = PC.get(dq, 0, &key, subnet, dnssecOK, receivedOverUDP);
      if (found == true) {
        auto removed = PC.expungeByName(ids.qname);
        BOOST_CHECK_EQUAL(removed, 1U);
        deleted += removed;
      }
    }
    BOOST_CHECK_EQUAL(PC.getSize(), counter - skipped - deleted);

    size_t matches=0;
    size_t expected=counter-skipped-deleted;
    for (; delcounter < counter; ++delcounter) {
      ids.qname = DNSName(std::to_string(delcounter))+DNSName(" hello");
      PacketBuffer query;
      GenericDNSPacketWriter<PacketBuffer> pwQ(query, ids.qname, QType::A, QClass::IN, 0);
      pwQ.getHeader()->rd = 1;
      uint32_t key = 0;
      boost::optional<Netmask> subnet;
      DNSQuestion dq(ids, query);
      if (PC.get(dq, pwQ.getHeader()->id, &key, subnet, dnssecOK, receivedOverUDP)) {
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

    /* nothing to remove */
    BOOST_CHECK_EQUAL(PC.purgeExpired(0, now), 0U);
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

  size_t counter = 0;
  size_t skipped = 0;
  ComboAddress remote;
  bool dnssecOK = false;
  const time_t now = time(nullptr);
  InternalQueryState ids;
  ids.qtype = QType::AAAA;
  ids.qclass = QClass::IN;
  ids.protocol = dnsdist::Protocol::DoUDP;

  try {
    for (counter = 0; counter < 100000; ++counter) {
      ids.qname = DNSName(std::to_string(counter) + ".powerdns.com.");

      PacketBuffer query;
      GenericDNSPacketWriter<PacketBuffer> pwQ(query, ids.qname, QType::AAAA, QClass::IN, 0);
      pwQ.getHeader()->rd = 1;

      PacketBuffer response;
      GenericDNSPacketWriter<PacketBuffer> pwR(response, ids.qname, QType::AAAA, QClass::IN, 0);
      pwR.getHeader()->rd = 1;
      pwR.getHeader()->ra = 1;
      pwR.getHeader()->qr = 1;
      pwR.getHeader()->id = pwQ.getHeader()->id;
      pwR.startRecord(ids.qname, QType::AAAA, 7200, QClass::IN, DNSResourceRecord::ANSWER);
      ComboAddress v6("2001:db8::1");
      pwR.xfrIP6(std::string(reinterpret_cast<const char*>(v6.sin6.sin6_addr.s6_addr), 16));
      pwR.commit();

      uint32_t key = 0;
      boost::optional<Netmask> subnet;
      DNSQuestion dq(ids, query);
      bool found = PC.get(dq, 0, &key, subnet, dnssecOK, receivedOverUDP);
      BOOST_CHECK_EQUAL(found, false);
      BOOST_CHECK(!subnet);

      PC.insert(key, subnet, *(getFlagsFromDNSHeader(dq.getHeader())), dnssecOK, ids.qname, QType::AAAA, QClass::IN, response, receivedOverUDP, 0, boost::none);

      found = PC.get(dq, pwR.getHeader()->id, &key, subnet, dnssecOK, receivedOverUDP, 0, true);
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
      ids.qname = DNSName(std::to_string(counter) + ".powerdns.com.");

      PacketBuffer query;
      GenericDNSPacketWriter<PacketBuffer> pwQ(query, ids.qname, QType::AAAA, QClass::IN, 0);
      pwQ.getHeader()->rd = 1;
      uint32_t key = 0;
      boost::optional<Netmask> subnet;
      DNSQuestion dq(ids, query);
      if (PC.get(dq, pwQ.getHeader()->id, &key, subnet, dnssecOK, receivedOverUDP)) {
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

    /* nothing to remove */
    BOOST_CHECK_EQUAL(PC.purgeExpired(0, now), 0U);
  }
  catch (const PDNSException& e) {
    cerr<<"Had error: "<<e.reason<<endl;
    throw;
  }
}

BOOST_AUTO_TEST_CASE(test_PacketCacheTCP) {
  const size_t maxEntries = 150000;
  DNSDistPacketCache PC(maxEntries, 86400, 1);
  InternalQueryState ids;
  ids.qtype = QType::A;
  ids.qclass = QClass::IN;
  ids.protocol = dnsdist::Protocol::DoUDP;

  ComboAddress remote;
  bool dnssecOK = false;
  try {
    DNSName a("tcp");
    ids.qname = a;

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
    pwR.commit();

    {
      /* UDP */
      uint32_t key = 0;
      boost::optional<Netmask> subnet;
      DNSQuestion dq(ids, query);
      bool found = PC.get(dq, 0, &key, subnet, dnssecOK, receivedOverUDP);
      BOOST_CHECK_EQUAL(found, false);
      BOOST_CHECK(!subnet);

      PC.insert(key, subnet, *(getFlagsFromDNSHeader(dq.getHeader())), dnssecOK, a, QType::A, QClass::IN, response, receivedOverUDP, RCode::NoError, boost::none);
      found = PC.get(dq, pwR.getHeader()->id, &key, subnet, dnssecOK, receivedOverUDP, 0, true);
      BOOST_CHECK_EQUAL(found, true);
      BOOST_CHECK(!subnet);
    }

    {
      /* same but over TCP */
      uint32_t key = 0;
      boost::optional<Netmask> subnet;
      ids.protocol = dnsdist::Protocol::DoTCP;
      DNSQuestion dq(ids, query);
      bool found = PC.get(dq, 0, &key, subnet, dnssecOK, !receivedOverUDP);
      BOOST_CHECK_EQUAL(found, false);
      BOOST_CHECK(!subnet);

      PC.insert(key, subnet, *(getFlagsFromDNSHeader(dq.getHeader())), dnssecOK, a, QType::A, QClass::IN, response, !receivedOverUDP, RCode::NoError, boost::none);
      found = PC.get(dq, pwR.getHeader()->id, &key, subnet, dnssecOK, !receivedOverUDP, 0, true);
      BOOST_CHECK_EQUAL(found, true);
      BOOST_CHECK(!subnet);
    }
  }
  catch(PDNSException& e) {
    cerr<<"Had error: "<<e.reason<<endl;
    throw;
  }
}

BOOST_AUTO_TEST_CASE(test_PacketCacheServFailTTL) {
  const size_t maxEntries = 150000;
  DNSDistPacketCache PC(maxEntries, 86400, 1);
  InternalQueryState ids;
  ids.qtype = QType::A;
  ids.qclass = QClass::IN;
  ids.protocol = dnsdist::Protocol::DoUDP;

  ComboAddress remote;
  bool dnssecOK = false;
  try {
    DNSName a = DNSName("servfail");
    ids.qname = a;

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
    DNSQuestion dq(ids, query);
    bool found = PC.get(dq, 0, &key, subnet, dnssecOK, receivedOverUDP);
    BOOST_CHECK_EQUAL(found, false);
    BOOST_CHECK(!subnet);

    // Insert with failure-TTL of 0 (-> should not enter cache).
    PC.insert(key, subnet, *(getFlagsFromDNSHeader(dq.getHeader())), dnssecOK, a, QType::A, QClass::IN, response, receivedOverUDP, RCode::ServFail, boost::optional<uint32_t>(0));
    found = PC.get(dq, pwR.getHeader()->id, &key, subnet, dnssecOK, receivedOverUDP, 0, true);
    BOOST_CHECK_EQUAL(found, false);
    BOOST_CHECK(!subnet);

    // Insert with failure-TTL non-zero (-> should enter cache).
    PC.insert(key, subnet, *(getFlagsFromDNSHeader(dq.getHeader())), dnssecOK, a, QType::A, QClass::IN, response, receivedOverUDP, RCode::ServFail, boost::optional<uint32_t>(300));
    found = PC.get(dq, pwR.getHeader()->id, &key, subnet, dnssecOK, receivedOverUDP, 0, true);
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

  ComboAddress remote;
  bool dnssecOK = false;
  InternalQueryState ids;
  ids.qtype = QType::A;
  ids.qclass = QClass::IN;
  ids.protocol = dnsdist::Protocol::DoUDP;

  try {
    DNSName name("nodata");
    ids.qname = name;
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
    DNSQuestion dq(ids, query);
    bool found = PC.get(dq, 0, &key, subnet, dnssecOK, receivedOverUDP);
    BOOST_CHECK_EQUAL(found, false);
    BOOST_CHECK(!subnet);

    PC.insert(key, subnet, *(getFlagsFromDNSHeader(dq.getHeader())), dnssecOK, name, QType::A, QClass::IN, response, receivedOverUDP, RCode::NoError, boost::none);
    found = PC.get(dq, pwR.getHeader()->id, &key, subnet, dnssecOK, receivedOverUDP, 0, true);
    BOOST_CHECK_EQUAL(found, true);
    BOOST_CHECK(!subnet);

    sleep(2);
    /* it should have expired by now */
    found = PC.get(dq, pwR.getHeader()->id, &key, subnet, dnssecOK, receivedOverUDP, 0, true);
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

  InternalQueryState ids;
  ids.qtype = QType::A;
  ids.qclass = QClass::IN;
  ids.protocol = dnsdist::Protocol::DoUDP;

  ComboAddress remote;
  bool dnssecOK = false;
  try {
    DNSName name("nxdomain");
    ids.qname = name;
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
    DNSQuestion dq(ids, query);
    bool found = PC.get(dq, 0, &key, subnet, dnssecOK, receivedOverUDP);
    BOOST_CHECK_EQUAL(found, false);
    BOOST_CHECK(!subnet);

    PC.insert(key, subnet, *(getFlagsFromDNSHeader(dq.getHeader())), dnssecOK, name, QType::A, QClass::IN, response, receivedOverUDP, RCode::NXDomain, boost::none);
    found = PC.get(dq, pwR.getHeader()->id, &key, subnet, dnssecOK, receivedOverUDP, 0, true);
    BOOST_CHECK_EQUAL(found, true);
    BOOST_CHECK(!subnet);

    sleep(2);
    /* it should have expired by now */
    found = PC.get(dq, pwR.getHeader()->id, &key, subnet, dnssecOK, receivedOverUDP, 0, true);
    BOOST_CHECK_EQUAL(found, false);
    BOOST_CHECK(!subnet);
  }
  catch(const PDNSException& e) {
    cerr<<"Had error: "<<e.reason<<endl;
    throw;
  }
}

BOOST_AUTO_TEST_CASE(test_PacketCacheTruncated) {
  const size_t maxEntries = 150000;
  DNSDistPacketCache PC(maxEntries, /* maxTTL */ 86400, /* minTTL */ 1, /* tempFailureTTL */ 60, /* maxNegativeTTL */ 1);

  InternalQueryState ids;
  ids.qtype = QType::A;
  ids.qclass = QClass::IN;
  ids.protocol = dnsdist::Protocol::DoUDP;
  ids.queryRealTime.start();  // does not have to be accurate ("realTime") in tests
  bool dnssecOK = false;

  try {
    ids.qname = DNSName("truncated");
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> pwQ(query, ids.qname, QType::A, QClass::IN, 0);
    pwQ.getHeader()->rd = 1;

    PacketBuffer response;
    GenericDNSPacketWriter<PacketBuffer> pwR(response, ids.qname, QType::A, QClass::IN, 0);
    pwR.getHeader()->rd = 1;
    pwR.getHeader()->ra = 0;
    pwR.getHeader()->qr = 1;
    pwR.getHeader()->tc = 1;
    pwR.getHeader()->rcode = RCode::NoError;
    pwR.getHeader()->id = pwQ.getHeader()->id;
    pwR.commit();
    pwR.startRecord(ids.qname, QType::A, 7200, QClass::IN, DNSResourceRecord::ANSWER);
    pwR.xfr32BitInt(0x01020304);
    pwR.commit();

    uint32_t key = 0;
    boost::optional<Netmask> subnet;
    DNSQuestion dq(ids, query);
    bool found = PC.get(dq, 0, &key, subnet, dnssecOK, receivedOverUDP);
    BOOST_CHECK_EQUAL(found, false);
    BOOST_CHECK(!subnet);

    PC.insert(key, subnet, *(getFlagsFromDNSHeader(dq.getHeader())), dnssecOK, ids.qname, QType::A, QClass::IN, response, receivedOverUDP, RCode::NXDomain, boost::none);

    bool allowTruncated = true;
    found = PC.get(dq, pwR.getHeader()->id, &key, subnet, dnssecOK, receivedOverUDP, 0, true, allowTruncated);
    BOOST_CHECK_EQUAL(found, true);
    BOOST_CHECK(!subnet);

    allowTruncated = false;
    found = PC.get(dq, pwR.getHeader()->id, &key, subnet, dnssecOK, receivedOverUDP, 0, true, allowTruncated);
    BOOST_CHECK_EQUAL(found, false);
}
  catch(const PDNSException& e) {
    cerr<<"Had error: "<<e.reason<<endl;
    throw;
  }
}

static DNSDistPacketCache g_PC(500000);

static void threadMangler(unsigned int offset)
{
  InternalQueryState ids;
  ids.qtype = QType::A;
  ids.qclass = QClass::IN;
  ids.protocol = dnsdist::Protocol::DoUDP;

  try {
    ComboAddress remote;
    bool dnssecOK = false;
    for(unsigned int counter=0; counter < 100000; ++counter) {
      ids.qname = DNSName("hello ")+DNSName(std::to_string(counter+offset));
      PacketBuffer query;
      GenericDNSPacketWriter<PacketBuffer> pwQ(query, ids.qname, QType::A, QClass::IN, 0);
      pwQ.getHeader()->rd = 1;

      PacketBuffer response;
      GenericDNSPacketWriter<PacketBuffer> pwR(response, ids.qname, QType::A, QClass::IN, 0);
      pwR.getHeader()->rd = 1;
      pwR.getHeader()->ra = 1;
      pwR.getHeader()->qr = 1;
      pwR.getHeader()->id = pwQ.getHeader()->id;
      pwR.startRecord(ids.qname, QType::A, 3600, QClass::IN, DNSResourceRecord::ANSWER);
      pwR.xfr32BitInt(0x01020304);
      pwR.commit();

      uint32_t key = 0;
      boost::optional<Netmask> subnet;
      DNSQuestion dq(ids, query);
      g_PC.get(dq, 0, &key, subnet, dnssecOK, receivedOverUDP);

      g_PC.insert(key, subnet, *(getFlagsFromDNSHeader(dq.getHeader())), dnssecOK, ids.qname, QType::A, QClass::IN, response, receivedOverUDP, 0, boost::none);
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
  InternalQueryState ids;
  ids.qtype = QType::A;
  ids.qclass = QClass::IN;
  ids.qname = DNSName("www.powerdns.com.");
  ids.protocol = dnsdist::Protocol::DoUDP;
  bool dnssecOK = false;
  try
  {
    ComboAddress remote;
    for(unsigned int counter=0; counter < 100000; ++counter) {
      ids.qname = DNSName("hello ")+DNSName(std::to_string(counter+offset));
      PacketBuffer query;
      GenericDNSPacketWriter<PacketBuffer> pwQ(query, ids.qname, QType::A, QClass::IN, 0);
      pwQ.getHeader()->rd = 1;

      uint32_t key = 0;
      boost::optional<Netmask> subnet;
      DNSQuestion dq(ids, query);
      bool found = g_PC.get(dq, 0, &key, subnet, dnssecOK, receivedOverUDP);
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

  InternalQueryState ids;
  ids.qtype = QType::AAAA;
  ids.qclass = QClass::IN;
  ids.qname = DNSName("www.powerdns.com.");
  ids.protocol = dnsdist::Protocol::DoUDP;
  uint16_t qid = 0x42;
  uint32_t key;
  uint32_t secondKey;
  boost::optional<Netmask> subnetOut;
  bool dnssecOK = false;

  /* lookup for a query with a first ECS value,
     insert a corresponding response */
  {
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> pwQ(query, ids.qname, ids.qtype, QClass::IN, 0);
    pwQ.getHeader()->rd = 1;
    pwQ.getHeader()->id = qid;
    GenericDNSPacketWriter<PacketBuffer>::optvect_t ednsOptions;
    EDNSSubnetOpts opt;
    opt.source = Netmask("10.0.59.220/32");
    ednsOptions.emplace_back(EDNSOptionCode::ECS, makeEDNSSubnetOptsString(opt));
    pwQ.addOpt(512, 0, 0, ednsOptions);
    pwQ.commit();

    ComboAddress remote("192.0.2.1");
    ids.queryRealTime.start();
    DNSQuestion dq(ids, query);
    bool found = PC.get(dq, 0, &key, subnetOut, dnssecOK, receivedOverUDP);
    BOOST_CHECK_EQUAL(found, false);
    BOOST_REQUIRE(subnetOut);
    BOOST_CHECK_EQUAL(subnetOut->toString(), opt.source.toString());

    PacketBuffer response;
    GenericDNSPacketWriter<PacketBuffer> pwR(response, ids.qname, ids.qtype, QClass::IN, 0);
    pwR.getHeader()->rd = 1;
    pwR.getHeader()->id = qid;
    pwR.startRecord(ids.qname, ids.qtype, 100, QClass::IN, DNSResourceRecord::ANSWER);
    ComboAddress v6("::1");
    pwR.xfrCAWithoutPort(6, v6);
    pwR.commit();
    pwR.addOpt(512, 0, 0, ednsOptions);
    pwR.commit();

    PC.insert(key, subnetOut, *(getFlagsFromDNSHeader(pwR.getHeader())), dnssecOK, ids.qname, ids.qtype, QClass::IN, response, receivedOverUDP, RCode::NoError, boost::none);
    BOOST_CHECK_EQUAL(PC.getSize(), 1U);

    found = PC.get(dq, 0, &key, subnetOut, dnssecOK, receivedOverUDP);
    BOOST_CHECK_EQUAL(found, true);
    BOOST_REQUIRE(subnetOut);
    BOOST_CHECK_EQUAL(subnetOut->toString(), opt.source.toString());
  }

  /* now lookup for the same query with a different ECS value,
     we should get the same key (collision) but no match */
  {
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> pwQ(query, ids.qname, ids.qtype, QClass::IN, 0);
    pwQ.getHeader()->rd = 1;
    pwQ.getHeader()->id = qid;
    GenericDNSPacketWriter<PacketBuffer>::optvect_t ednsOptions;
    EDNSSubnetOpts opt;
    opt.source = Netmask("10.0.167.48/32");
    ednsOptions.emplace_back(EDNSOptionCode::ECS, makeEDNSSubnetOptsString(opt));
    pwQ.addOpt(512, 0, 0, ednsOptions);
    pwQ.commit();

    ComboAddress remote("192.0.2.1");
    ids.queryRealTime.start();
    DNSQuestion dq(ids, query);
    bool found = PC.get(dq, 0, &secondKey, subnetOut, dnssecOK, receivedOverUDP);
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
          GenericDNSPacketWriter<PacketBuffer> pwFQ(secondQuery, ids.qname, QType::AAAA, QClass::IN, 0);
          pwFQ.getHeader()->rd = 1;
          pwFQ.getHeader()->qr = false;
          pwFQ.getHeader()->id = 0x42;
          opt.source = Netmask("10." + std::to_string(idxA) + "." + std::to_string(idxB) + "." + std::to_string(idxC) + "/32");
          ednsOptions.clear();
          ednsOptions.emplace_back(EDNSOptionCode::ECS, makeEDNSSubnetOptsString(opt));
          pwFQ.addOpt(512, 0, 0, ednsOptions);
          pwFQ.commit();
          secondKey = pc.getKey(ids.qname.toDNSString(), ids.qname.wirelength(), secondQuery, false);
          auto pair = colMap.emplace(secondKey, opt.source);
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

  InternalQueryState ids;
  ids.qtype = QType::AAAA;
  ids.qclass = QClass::IN;
  ids.qname = DNSName("www.powerdns.com.");
  ids.protocol = dnsdist::Protocol::DoUDP;
  uint16_t qid = 0x42;
  uint32_t key;
  boost::optional<Netmask> subnetOut;

  /* lookup for a query with DNSSEC OK,
     insert a corresponding response with DO set,
     check that it doesn't match without DO, but does with it */
  {
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> pwQ(query, ids.qname, ids.qtype, QClass::IN, 0);
    pwQ.getHeader()->rd = 1;
    pwQ.getHeader()->id = qid;
    pwQ.addOpt(512, 0, EDNS_HEADER_FLAG_DO);
    pwQ.commit();

    ComboAddress remote("192.0.2.1");
    ids.queryRealTime.start();
    ids.origRemote = remote;
    DNSQuestion dq(ids, query);
    bool found = PC.get(dq, 0, &key, subnetOut, true, receivedOverUDP);
    BOOST_CHECK_EQUAL(found, false);

    PacketBuffer response;
    GenericDNSPacketWriter<PacketBuffer> pwR(response, ids.qname, ids.qtype, QClass::IN, 0);
    pwR.getHeader()->rd = 1;
    pwR.getHeader()->id = qid;
    pwR.startRecord(ids.qname, ids.qtype, 100, QClass::IN, DNSResourceRecord::ANSWER);
    ComboAddress v6("::1");
    pwR.xfrCAWithoutPort(6, v6);
    pwR.commit();
    pwR.addOpt(512, 0, EDNS_HEADER_FLAG_DO);
    pwR.commit();

    PC.insert(key, subnetOut, *(getFlagsFromDNSHeader(pwR.getHeader())), /* DNSSEC OK is set */ true, ids.qname, ids.qtype, QClass::IN, response, receivedOverUDP, RCode::NoError, boost::none);
    BOOST_CHECK_EQUAL(PC.getSize(), 1U);

    found = PC.get(dq, 0, &key, subnetOut, false, receivedOverUDP);
    BOOST_CHECK_EQUAL(found, false);

    found = PC.get(dq, 0, &key, subnetOut, true, receivedOverUDP);
    BOOST_CHECK_EQUAL(found, true);
  }

}

BOOST_AUTO_TEST_CASE(test_PacketCacheInspection) {
  const size_t maxEntries = 100;
  DNSDistPacketCache PC(maxEntries, 86400, 1);
  BOOST_CHECK_EQUAL(PC.getSize(), 0U);

  ComboAddress remote;
  bool dnssecOK = false;

  uint32_t key = 0;

  /* insert powerdns.com A 192.0.2.1, 192.0.2.2 */
  {
    DNSName qname("powerdns.com");
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> pwQ(query, qname, QType::A, QClass::IN, 0);
    pwQ.getHeader()->rd = 1;

    PacketBuffer response;
    GenericDNSPacketWriter<PacketBuffer> pwR(response, qname, QType::A, QClass::IN, 0);
    pwR.getHeader()->rd = 1;
    pwR.getHeader()->ra = 1;
    pwR.getHeader()->qr = 1;
    pwR.getHeader()->id = pwQ.getHeader()->id;
    {
      ComboAddress addr("192.0.2.1");
      pwR.startRecord(qname, QType::A, 7200, QClass::IN, DNSResourceRecord::ANSWER);
      pwR.xfrCAWithoutPort(4, addr);
      pwR.commit();
    }
    {
      ComboAddress addr("192.0.2.2");
      pwR.startRecord(qname, QType::A, 7200, QClass::IN, DNSResourceRecord::ANSWER);
      pwR.xfrCAWithoutPort(4, addr);
      pwR.commit();
    }

    PC.insert(key++, boost::none, *getFlagsFromDNSHeader(pwQ.getHeader()), dnssecOK, qname, QType::A, QClass::IN, response, receivedOverUDP, 0, boost::none);
    BOOST_CHECK_EQUAL(PC.getSize(), key);
  }

  /* insert powerdns1.com A 192.0.2.3, 192.0.2.4, AAAA 2001:db8::3, 2001:db8::4 */
  {
    DNSName qname("powerdns1.com");
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> pwQ(query, qname, QType::A, QClass::IN, 0);
    pwQ.getHeader()->rd = 1;

    PacketBuffer response;
    GenericDNSPacketWriter<PacketBuffer> pwR(response, qname, QType::A, QClass::IN, 0);
    pwR.getHeader()->rd = 1;
    pwR.getHeader()->ra = 1;
    pwR.getHeader()->qr = 1;
    pwR.getHeader()->id = pwQ.getHeader()->id;
    {
      ComboAddress addr("192.0.2.3");
      pwR.startRecord(qname, QType::A, 7200, QClass::IN, DNSResourceRecord::ANSWER);
      pwR.xfrCAWithoutPort(4, addr);
      pwR.commit();
    }
    {
      ComboAddress addr("192.0.2.4");
      pwR.startRecord(qname, QType::A, 7200, QClass::IN, DNSResourceRecord::ANSWER);
      pwR.xfrCAWithoutPort(4, addr);
      pwR.commit();
    }
    {
      ComboAddress addr("2001:db8::3");
      pwR.startRecord(qname, QType::AAAA, 7200, QClass::IN, DNSResourceRecord::ADDITIONAL);
      pwR.xfrCAWithoutPort(6, addr);
      pwR.commit();
    }
    {
      ComboAddress addr("2001:db8::4");
      pwR.startRecord(qname, QType::AAAA, 7200, QClass::IN, DNSResourceRecord::ADDITIONAL);
      pwR.xfrCAWithoutPort(6, addr);
      pwR.commit();
    }

    PC.insert(key++, boost::none, *getFlagsFromDNSHeader(pwQ.getHeader()), dnssecOK, qname, QType::A, QClass::IN, response, receivedOverUDP, 0, boost::none);
    BOOST_CHECK_EQUAL(PC.getSize(), key);
  }

  /* insert powerdns2.com NODATA */
  {
    DNSName qname("powerdns2.com");
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> pwQ(query, qname, QType::A, QClass::IN, 0);
    pwQ.getHeader()->rd = 1;

    PacketBuffer response;
    GenericDNSPacketWriter<PacketBuffer> pwR(response, qname, QType::A, QClass::IN, 0);
    pwR.getHeader()->rd = 1;
    pwR.getHeader()->ra = 1;
    pwR.getHeader()->qr = 1;
    pwR.getHeader()->id = pwQ.getHeader()->id;
    pwR.commit();
    pwR.startRecord(qname, QType::SOA, 86400, QClass::IN, DNSResourceRecord::AUTHORITY);
    pwR.commit();
    pwR.addOpt(4096, 0, 0);
    pwR.commit();

    PC.insert(key++, boost::none, *getFlagsFromDNSHeader(pwQ.getHeader()), dnssecOK, qname, QType::A, QClass::IN, response, receivedOverUDP, 0, boost::none);
    BOOST_CHECK_EQUAL(PC.getSize(), key);
  }

  /* insert powerdns3.com AAAA 2001:db8::4, 2001:db8::5 */
  {
    DNSName qname("powerdns3.com");
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> pwQ(query, qname, QType::A, QClass::IN, 0);
    pwQ.getHeader()->rd = 1;

    PacketBuffer response;
    GenericDNSPacketWriter<PacketBuffer> pwR(response, qname, QType::A, QClass::IN, 0);
    pwR.getHeader()->rd = 1;
    pwR.getHeader()->ra = 1;
    pwR.getHeader()->qr = 1;
    pwR.getHeader()->id = pwQ.getHeader()->id;
    {
      ComboAddress addr("2001:db8::4");
      pwR.startRecord(qname, QType::AAAA, 7200, QClass::IN, DNSResourceRecord::ADDITIONAL);
      pwR.xfrCAWithoutPort(6, addr);
      pwR.commit();
    }
    {
      ComboAddress addr("2001:db8::5");
      pwR.startRecord(qname, QType::AAAA, 7200, QClass::IN, DNSResourceRecord::ADDITIONAL);
      pwR.xfrCAWithoutPort(6, addr);
      pwR.commit();
    }

    PC.insert(key++, boost::none, *getFlagsFromDNSHeader(pwQ.getHeader()), dnssecOK, qname, QType::A, QClass::IN, response, receivedOverUDP, 0, boost::none);
    BOOST_CHECK_EQUAL(PC.getSize(), key);
  }

  /* insert powerdns4.com A 192.0.2.1 */
  {
    DNSName qname("powerdns4.com");
    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> pwQ(query, qname, QType::A, QClass::IN, 0);
    pwQ.getHeader()->rd = 1;

    PacketBuffer response;
    GenericDNSPacketWriter<PacketBuffer> pwR(response, qname, QType::A, QClass::IN, 0);
    pwR.getHeader()->rd = 1;
    pwR.getHeader()->ra = 1;
    pwR.getHeader()->qr = 1;
    pwR.getHeader()->id = pwQ.getHeader()->id;
    {
      ComboAddress addr("192.0.2.1");
      pwR.startRecord(qname, QType::A, 7200, QClass::IN, DNSResourceRecord::ADDITIONAL);
      pwR.xfrCAWithoutPort(4, addr);
      pwR.commit();
    }

    PC.insert(key++, boost::none, *getFlagsFromDNSHeader(pwQ.getHeader()), dnssecOK, qname, QType::A, QClass::IN, response, receivedOverUDP, 0, boost::none);
    BOOST_CHECK_EQUAL(PC.getSize(), key);
  }

  {
    auto domains = PC.getDomainsContainingRecords(ComboAddress("192.0.2.1"));
    BOOST_CHECK_EQUAL(domains.size(), 2U);
    BOOST_CHECK_EQUAL(domains.count(DNSName("powerdns.com")), 1U);
    BOOST_CHECK_EQUAL(domains.count(DNSName("powerdns4.com")), 1U);
  }
  {
    auto domains = PC.getDomainsContainingRecords(ComboAddress("192.0.2.2"));
    BOOST_CHECK_EQUAL(domains.size(), 1U);
    BOOST_CHECK_EQUAL(domains.count(DNSName("powerdns.com")), 1U);
  }
  {
    auto domains = PC.getDomainsContainingRecords(ComboAddress("192.0.2.3"));
    BOOST_CHECK_EQUAL(domains.size(), 1U);
    BOOST_CHECK_EQUAL(domains.count(DNSName("powerdns1.com")), 1U);
  }
  {
    auto domains = PC.getDomainsContainingRecords(ComboAddress("192.0.2.4"));
    BOOST_CHECK_EQUAL(domains.size(), 1U);
    BOOST_CHECK_EQUAL(domains.count(DNSName("powerdns1.com")), 1U);
  }
  {
    auto domains = PC.getDomainsContainingRecords(ComboAddress("192.0.2.5"));
    BOOST_CHECK_EQUAL(domains.size(), 0U);
  }
  {
    auto domains = PC.getDomainsContainingRecords(ComboAddress("2001:db8::3"));
    BOOST_CHECK_EQUAL(domains.size(), 1U);
    BOOST_CHECK_EQUAL(domains.count(DNSName("powerdns1.com")), 1U);
  }
  {
    auto domains = PC.getDomainsContainingRecords(ComboAddress("2001:db8::4"));
    BOOST_CHECK_EQUAL(domains.size(), 2U);
    BOOST_CHECK_EQUAL(domains.count(DNSName("powerdns1.com")), 1U);
    BOOST_CHECK_EQUAL(domains.count(DNSName("powerdns3.com")), 1U);
  }
  {
    auto domains = PC.getDomainsContainingRecords(ComboAddress("2001:db8::5"));
    BOOST_CHECK_EQUAL(domains.size(), 1U);
    BOOST_CHECK_EQUAL(domains.count(DNSName("powerdns3.com")), 1U);
  }

  {
    auto records = PC.getRecordsForDomain(DNSName("powerdns.com"));
    BOOST_CHECK_EQUAL(records.size(), 2U);
    BOOST_CHECK_EQUAL(records.count(ComboAddress("192.0.2.1")), 1U);
    BOOST_CHECK_EQUAL(records.count(ComboAddress("192.0.2.2")), 1U);
  }

  {
    auto records = PC.getRecordsForDomain(DNSName("powerdns1.com"));
    BOOST_CHECK_EQUAL(records.size(), 4U);
    BOOST_CHECK_EQUAL(records.count(ComboAddress("192.0.2.3")), 1U);
    BOOST_CHECK_EQUAL(records.count(ComboAddress("192.0.2.4")), 1U);
    BOOST_CHECK_EQUAL(records.count(ComboAddress("2001:db8::3")), 1U);
    BOOST_CHECK_EQUAL(records.count(ComboAddress("2001:db8::4")), 1U);
  }

  {
    auto records = PC.getRecordsForDomain(DNSName("powerdns2.com"));
    BOOST_CHECK_EQUAL(records.size(), 0U);
  }

  {
    auto records = PC.getRecordsForDomain(DNSName("powerdns3.com"));
    BOOST_CHECK_EQUAL(records.size(), 2U);
    BOOST_CHECK_EQUAL(records.count(ComboAddress("2001:db8::4")), 1U);
    BOOST_CHECK_EQUAL(records.count(ComboAddress("2001:db8::4")), 1U);
  }

  {
    auto records = PC.getRecordsForDomain(DNSName("powerdns4.com"));
    BOOST_CHECK_EQUAL(records.size(), 1U);
    BOOST_CHECK_EQUAL(records.count(ComboAddress("192.0.2.1")), 1U);
  }

  {
    auto records = PC.getRecordsForDomain(DNSName("powerdns5.com"));
    BOOST_CHECK_EQUAL(records.size(), 0U);
  }
}

BOOST_AUTO_TEST_CASE(test_PacketCacheXFR) {
  const size_t maxEntries = 150000;
  DNSDistPacketCache PC(maxEntries, 86400, 1);
  BOOST_CHECK_EQUAL(PC.getSize(), 0U);

  const std::set<QType> xfrTypes = { QType::AXFR, QType::IXFR };
  for (const auto& type : xfrTypes) {
    bool dnssecOK = false;
    InternalQueryState ids;
    ids.qtype = type;
    ids.qclass = QClass::IN;
    ids.protocol = dnsdist::Protocol::DoUDP;
    ids.qname = DNSName("powerdns.com.");

    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> pwQ(query, ids.qname, ids.qtype, ids.qclass, 0);
    pwQ.getHeader()->rd = 1;

    PacketBuffer response;
    GenericDNSPacketWriter<PacketBuffer> pwR(response, ids.qname, ids.qtype, ids.qclass, 0);
    pwR.getHeader()->rd = 1;
    pwR.getHeader()->ra = 1;
    pwR.getHeader()->qr = 1;
    pwR.getHeader()->id = pwQ.getHeader()->id;
    pwR.startRecord(ids.qname, QType::A, 7200, QClass::IN, DNSResourceRecord::ANSWER);
    pwR.xfr32BitInt(0x01020304);
    pwR.commit();

    uint32_t key = 0;
    boost::optional<Netmask> subnet;
    DNSQuestion dq(ids, query);
    bool found = PC.get(dq, 0, &key, subnet, dnssecOK, receivedOverUDP);
    BOOST_CHECK_EQUAL(found, false);
    BOOST_CHECK(!subnet);

    PC.insert(key, subnet, *(getFlagsFromDNSHeader(dq.getHeader())), dnssecOK, ids.qname, ids.qtype, ids.qclass, response, receivedOverUDP, 0, boost::none);
    found = PC.get(dq, pwR.getHeader()->id, &key, subnet, dnssecOK, receivedOverUDP, 0, true);
    BOOST_CHECK_EQUAL(found, false);
  }
}

BOOST_AUTO_TEST_SUITE_END()
