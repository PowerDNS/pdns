#ifndef BOOST_TEST_DYN_LINK
#define BOOST_TEST_DYN_LINK
#endif

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

BOOST_AUTO_TEST_CASE(test_PacketCacheSimple)
{
  const DNSDistPacketCache::CacheSettings settings{
    .d_maxEntries = 150000,
    .d_maxTTL = 86400,
    .d_minTTL = 1,
  };
  DNSDistPacketCache localCache(settings);
  BOOST_CHECK_EQUAL(localCache.getSize(), 0U);

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
      ids.qname = DNSName(std::to_string(counter)) + DNSName(" hello");

      PacketBuffer query;
      GenericDNSPacketWriter<PacketBuffer> pwQ(query, ids.qname, QType::A, QClass::IN, 0);
      pwQ.getHeader()->rd = 1;

      PacketBuffer response;
      GenericDNSPacketWriter<PacketBuffer> pwR(response, ids.qname, QType::A, QClass::IN, 0);
      pwR.getHeader()->rd = 1;
      pwR.getHeader()->ra = 1;
      pwR.getHeader()->qr = 1;
      pwR.getHeader()->id = pwQ.getHeader()->id;
      pwR.startRecord(ids.qname, QType::A, 7200, QClass::IN, DNSResourceRecord::ANSWER);
      pwR.xfr32BitInt(0x01020304);
      pwR.commit();

      uint32_t key = 0;
      boost::optional<Netmask> subnet;
      DNSQuestion dnsQuestion(ids, query);
      bool found = localCache.get(dnsQuestion, 0, &key, subnet, dnssecOK);
      BOOST_CHECK_EQUAL(found, false);
      BOOST_CHECK(!subnet);

      localCache.insert(key, subnet, *(getFlagsFromDNSHeader(dnsQuestion.getHeader().get())), dnssecOK, ids.qname, QType::A, QClass::IN, response, 0, boost::none);

      found = localCache.get(dnsQuestion, pwR.getHeader()->id, &key, subnet, dnssecOK, 0, true);
      if (found) {
        BOOST_CHECK_EQUAL(dnsQuestion.getData().size(), response.size());
        int match = memcmp(dnsQuestion.getData().data(), response.data(), dnsQuestion.getData().size());
        BOOST_CHECK_EQUAL(match, 0);
        BOOST_CHECK(!subnet);
      }
      else {
        skipped++;
      }
    }

    BOOST_CHECK_EQUAL(skipped, localCache.getInsertCollisions());
    BOOST_CHECK_EQUAL(localCache.getSize(), counter - skipped);

    size_t deleted = 0;
    size_t delcounter = 0;
    for (delcounter = 0; delcounter < counter / 1000; ++delcounter) {
      ids.qname = DNSName(std::to_string(delcounter)) + DNSName(" hello");
      PacketBuffer query;
      GenericDNSPacketWriter<PacketBuffer> pwQ(query, ids.qname, QType::A, QClass::IN, 0);
      pwQ.getHeader()->rd = 1;
      uint32_t key = 0;
      boost::optional<Netmask> subnet;
      DNSQuestion dnsQuestion(ids, query);
      bool found = localCache.get(dnsQuestion, 0, &key, subnet, dnssecOK);
      if (found) {
        auto removed = localCache.expungeByName(ids.qname);
        BOOST_CHECK_EQUAL(removed, 1U);
        deleted += removed;
      }
    }
    BOOST_CHECK_EQUAL(localCache.getSize(), counter - skipped - deleted);

    size_t matches = 0;
    size_t expected = counter - skipped - deleted;
    for (; delcounter < counter; ++delcounter) {
      ids.qname = DNSName(std::to_string(delcounter)) + DNSName(" hello");
      PacketBuffer query;
      GenericDNSPacketWriter<PacketBuffer> pwQ(query, ids.qname, QType::A, QClass::IN, 0);
      pwQ.getHeader()->rd = 1;
      uint32_t key = 0;
      boost::optional<Netmask> subnet;
      DNSQuestion dnsQuestion(ids, query);
      if (localCache.get(dnsQuestion, pwQ.getHeader()->id, &key, subnet, dnssecOK)) {
        matches++;
      }
    }

    /* in the unlikely event that the test took so long that the entries did expire.. */
    auto expired = localCache.purgeExpired(0, now);
    BOOST_CHECK_EQUAL(matches + expired, expected);

    auto remaining = localCache.getSize();
    auto removed = localCache.expungeByName(DNSName(" hello"), QType::ANY, true);
    BOOST_CHECK_EQUAL(localCache.getSize(), 0U);
    BOOST_CHECK_EQUAL(removed, remaining);

    /* nothing to remove */
    BOOST_CHECK_EQUAL(localCache.purgeExpired(0, now), 0U);
  }
  catch (const PDNSException& e) {
    cerr << "Had error: " << e.reason << endl;
    throw;
  }
}

BOOST_AUTO_TEST_CASE(test_PacketCacheSharded)
{
  const DNSDistPacketCache::CacheSettings settings{
    .d_maxEntries = 150000,
    .d_maxTTL = 86400,
    .d_minTTL = 1,
    .d_tempFailureTTL = 60,
    .d_maxNegativeTTL = 3600,
    .d_staleTTL = 60,
    .d_shardCount = 10,
    .d_dontAge = false,
  };
  DNSDistPacketCache localCache(settings);
  BOOST_CHECK_EQUAL(localCache.getSize(), 0U);

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
      ComboAddress v6addr("2001:db8::1");
      pwR.xfrCAWithoutPort(6, v6addr);
      pwR.commit();

      uint32_t key = 0;
      boost::optional<Netmask> subnet;
      DNSQuestion dnsQuestion(ids, query);
      bool found = localCache.get(dnsQuestion, 0, &key, subnet, dnssecOK);
      BOOST_CHECK_EQUAL(found, false);
      BOOST_CHECK(!subnet);

      localCache.insert(key, subnet, *(getFlagsFromDNSHeader(dnsQuestion.getHeader().get())), dnssecOK, ids.qname, QType::AAAA, QClass::IN, response, 0, boost::none);

      found = localCache.get(dnsQuestion, pwR.getHeader()->id, &key, subnet, dnssecOK, 0, true);
      if (found) {
        BOOST_CHECK_EQUAL(dnsQuestion.getData().size(), response.size());
        int match = memcmp(dnsQuestion.getData().data(), response.data(), dnsQuestion.getData().size());
        BOOST_CHECK_EQUAL(match, 0);
        BOOST_CHECK(!subnet);
      }
      else {
        skipped++;
      }
    }

    BOOST_CHECK_EQUAL(skipped, localCache.getInsertCollisions());
    BOOST_CHECK_EQUAL(localCache.getSize(), counter - skipped);

    size_t matches = 0;
    for (counter = 0; counter < 100000; ++counter) {
      ids.qname = DNSName(std::to_string(counter) + ".powerdns.com.");

      PacketBuffer query;
      GenericDNSPacketWriter<PacketBuffer> pwQ(query, ids.qname, QType::AAAA, QClass::IN, 0);
      pwQ.getHeader()->rd = 1;
      uint32_t key = 0;
      boost::optional<Netmask> subnet;
      DNSQuestion dnsQuestion(ids, query);
      if (localCache.get(dnsQuestion, pwQ.getHeader()->id, &key, subnet, dnssecOK)) {
        matches++;
      }
    }

    BOOST_CHECK_EQUAL(matches, counter - skipped);

    auto remaining = localCache.getSize();

    /* no entry should have expired */
    auto expired = localCache.purgeExpired(0, now);
    BOOST_CHECK_EQUAL(expired, 0U);

    /* but after the TTL .. let's ask for at most 1k entries */
    auto removed = localCache.purgeExpired(1000, now + 7200 + 3600);
    BOOST_CHECK_EQUAL(removed, remaining - 1000U);
    BOOST_CHECK_EQUAL(localCache.getSize(), 1000U);

    /* now remove everything */
    removed = localCache.purgeExpired(0, now + 7200 + 3600);
    BOOST_CHECK_EQUAL(removed, 1000U);
    BOOST_CHECK_EQUAL(localCache.getSize(), 0U);

    /* nothing to remove */
    BOOST_CHECK_EQUAL(localCache.purgeExpired(0, now), 0U);
  }
  catch (const PDNSException& e) {
    cerr << "Had error: " << e.reason << endl;
    throw;
  }
}

BOOST_AUTO_TEST_CASE(test_PacketCacheServFailTTL)
{
  const DNSDistPacketCache::CacheSettings settings{
    .d_maxEntries = 150000,
    .d_maxTTL = 86400,
    .d_minTTL = 1,
  };
  DNSDistPacketCache localCache(settings);
  InternalQueryState ids;
  ids.qtype = QType::A;
  ids.qclass = QClass::IN;
  ids.protocol = dnsdist::Protocol::DoUDP;

  ComboAddress remote;
  bool dnssecOK = false;
  try {
    ids.qname = DNSName("servfail");

    PacketBuffer query;
    GenericDNSPacketWriter<PacketBuffer> pwQ(query, ids.qname, QType::A, QClass::IN, 0);
    pwQ.getHeader()->rd = 1;

    PacketBuffer response;
    GenericDNSPacketWriter<PacketBuffer> pwR(response, ids.qname, QType::A, QClass::IN, 0);
    pwR.getHeader()->rd = 1;
    pwR.getHeader()->ra = 0;
    pwR.getHeader()->qr = 1;
    pwR.getHeader()->rcode = RCode::ServFail;
    pwR.getHeader()->id = pwQ.getHeader()->id;
    pwR.commit();

    uint32_t key = 0;
    boost::optional<Netmask> subnet;
    DNSQuestion dnsQuestion(ids, query);
    bool found = localCache.get(dnsQuestion, 0, &key, subnet, dnssecOK);
    BOOST_CHECK_EQUAL(found, false);
    BOOST_CHECK(!subnet);

    // Insert with failure-TTL of 0 (-> should not enter cache).
    localCache.insert(key, subnet, *(getFlagsFromDNSHeader(dnsQuestion.getHeader().get())), dnssecOK, ids.qname, QType::A, QClass::IN, response, RCode::ServFail, boost::optional<uint32_t>(0));
    found = localCache.get(dnsQuestion, pwR.getHeader()->id, &key, subnet, dnssecOK, 0, true);
    BOOST_CHECK_EQUAL(found, false);
    BOOST_CHECK(!subnet);

    // Insert with failure-TTL non-zero (-> should enter cache).
    localCache.insert(key, subnet, *(getFlagsFromDNSHeader(dnsQuestion.getHeader().get())), dnssecOK, ids.qname, QType::A, QClass::IN, response, RCode::ServFail, boost::optional<uint32_t>(300));
    found = localCache.get(dnsQuestion, pwR.getHeader()->id, &key, subnet, dnssecOK, 0, true);
    BOOST_CHECK_EQUAL(found, true);
    BOOST_CHECK(!subnet);
  }
  catch (PDNSException& e) {
    cerr << "Had error: " << e.reason << endl;
    throw;
  }
}

BOOST_AUTO_TEST_CASE(test_PacketCacheNoDataTTL)
{
  const DNSDistPacketCache::CacheSettings settings{
    .d_maxEntries = 150000,
    .d_maxTTL = 86400,
    .d_minTTL = 1,
    .d_tempFailureTTL = 60,
    .d_maxNegativeTTL = 1,
  };
  DNSDistPacketCache localCache(settings);

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
    DNSQuestion dnsQuestion(ids, query);
    bool found = localCache.get(dnsQuestion, 0, &key, subnet, dnssecOK);
    BOOST_CHECK_EQUAL(found, false);
    BOOST_CHECK(!subnet);

    localCache.insert(key, subnet, *(getFlagsFromDNSHeader(dnsQuestion.getHeader().get())), dnssecOK, name, QType::A, QClass::IN, response, RCode::NoError, boost::none);
    found = localCache.get(dnsQuestion, pwR.getHeader()->id, &key, subnet, dnssecOK, 0, true);
    BOOST_CHECK_EQUAL(found, true);
    BOOST_CHECK(!subnet);

    std::this_thread::sleep_for(std::chrono::seconds(2));
    /* it should have expired by now */
    found = localCache.get(dnsQuestion, pwR.getHeader()->id, &key, subnet, dnssecOK, 0, true);
    BOOST_CHECK_EQUAL(found, false);
    BOOST_CHECK(!subnet);
  }
  catch (const PDNSException& e) {
    cerr << "Had error: " << e.reason << endl;
    throw;
  }
}

BOOST_AUTO_TEST_CASE(test_PacketCacheNXDomainTTL)
{
  const DNSDistPacketCache::CacheSettings settings{
    .d_maxEntries = 150000,
    .d_maxTTL = 86400,
    .d_minTTL = 1,
    .d_tempFailureTTL = 60,
    .d_maxNegativeTTL = 1,
  };
  DNSDistPacketCache localCache(settings);

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
    DNSQuestion dnsQuestion(ids, query);
    bool found = localCache.get(dnsQuestion, 0, &key, subnet, dnssecOK);
    BOOST_CHECK_EQUAL(found, false);
    BOOST_CHECK(!subnet);

    localCache.insert(key, subnet, *(getFlagsFromDNSHeader(dnsQuestion.getHeader().get())), dnssecOK, name, QType::A, QClass::IN, response, RCode::NXDomain, boost::none);
    found = localCache.get(dnsQuestion, pwR.getHeader()->id, &key, subnet, dnssecOK, 0, true);
    BOOST_CHECK_EQUAL(found, true);
    BOOST_CHECK(!subnet);

    std::this_thread::sleep_for(std::chrono::seconds(2));
    /* it should have expired by now */
    found = localCache.get(dnsQuestion, pwR.getHeader()->id, &key, subnet, dnssecOK, 0, true);
    BOOST_CHECK_EQUAL(found, false);
    BOOST_CHECK(!subnet);
  }
  catch (const PDNSException& e) {
    cerr << "Had error: " << e.reason << endl;
    throw;
  }
}

BOOST_AUTO_TEST_CASE(test_PacketCacheMaximumSize)
{
  InternalQueryState ids;
  ids.qtype = QType::A;
  ids.qclass = QClass::IN;
  ids.protocol = dnsdist::Protocol::DoUDP;

  ComboAddress remote;
  bool dnssecOK = false;
  ids.qname = DNSName("maximum.size");

  PacketBuffer query;
  uint16_t queryID{0};
  {
    GenericDNSPacketWriter<PacketBuffer> pwQ(query, ids.qname, QType::AAAA, QClass::IN, 0);
    pwQ.getHeader()->rd = 1;
    queryID = pwQ.getHeader()->id;
  }

  PacketBuffer response;
  {
    GenericDNSPacketWriter<PacketBuffer> pwR(response, ids.qname, QType::AAAA, QClass::IN, 0);
    pwR.getHeader()->rd = 1;
    pwR.getHeader()->ra = 1;
    pwR.getHeader()->qr = 1;
    pwR.getHeader()->id = queryID;
    pwR.startRecord(ids.qname, QType::AAAA, 7200, QClass::IN, DNSResourceRecord::ANSWER);
    ComboAddress v6addr("2001:db8::1");
    pwR.xfrCAWithoutPort(6, v6addr);
    pwR.commit();
  }

  {
    /* first, we set the maximum entry size to the response packet size */
    const DNSDistPacketCache::CacheSettings settings{
      .d_maxEntries = 150000,
      .d_maximumEntrySize = response.size(),
      .d_maxTTL = 86400,
      .d_minTTL = 1,
    };
    DNSDistPacketCache packetCache(settings);

    {
      /* UDP */
      uint32_t key = 0;
      boost::optional<Netmask> subnet;
      DNSQuestion dnsQuestion(ids, query);
      bool found = packetCache.get(dnsQuestion, 0, &key, subnet, dnssecOK);
      BOOST_CHECK_EQUAL(found, false);
      BOOST_CHECK(!subnet);

      packetCache.insert(key, subnet, *(getFlagsFromDNSHeader(dnsQuestion.getHeader().get())), dnssecOK, ids.qname, QType::A, QClass::IN, response, RCode::NoError, boost::none);
      found = packetCache.get(dnsQuestion, queryID, &key, subnet, dnssecOK, 0, true);
      BOOST_CHECK_EQUAL(found, true);
      BOOST_CHECK(!subnet);
    }
  }

  {
    /* then we set it slightly below response packet size */
    const DNSDistPacketCache::CacheSettings settings{
      .d_maxEntries = 150000,
      .d_maximumEntrySize = response.size() - 1,
      .d_maxTTL = 86400,
      .d_minTTL = 1,
    };
    DNSDistPacketCache packetCache(settings);

    {
      /* UDP */
      uint32_t key = 0;
      boost::optional<Netmask> subnet;
      DNSQuestion dnsQuestion(ids, query);
      bool found = packetCache.get(dnsQuestion, 0, &key, subnet, dnssecOK);
      BOOST_CHECK_EQUAL(found, false);
      BOOST_CHECK(!subnet);

      packetCache.insert(key, subnet, *(getFlagsFromDNSHeader(dnsQuestion.getHeader().get())), dnssecOK, ids.qname, QType::A, QClass::IN, response, RCode::NoError, boost::none);
      found = packetCache.get(dnsQuestion, queryID, &key, subnet, dnssecOK, 0, true);
      BOOST_CHECK_EQUAL(found, false);
    }
  }

  /* now we generate a very big response packet, it should be cached (although in practice dnsdist will refuse to cache it for the UDP case)  */
  response.clear();
  {
    GenericDNSPacketWriter<PacketBuffer> pwR(response, ids.qname, QType::AAAA, QClass::IN, 0);
    pwR.getHeader()->rd = 1;
    pwR.getHeader()->ra = 1;
    pwR.getHeader()->qr = 1;
    pwR.getHeader()->id = queryID;
    for (size_t idx = 0; idx < 1000; idx++) {
      pwR.startRecord(ids.qname, QType::AAAA, 7200, QClass::IN, DNSResourceRecord::ANSWER);
      ComboAddress v6addr("2001:db8::1");
      pwR.xfrCAWithoutPort(6, v6addr);
    }
    pwR.commit();
  }

  BOOST_REQUIRE_GT(response.size(), 4096U);

  {
    /* then we set it slightly below response packet size */
    const DNSDistPacketCache::CacheSettings settings{
      .d_maxEntries = 150000,
      .d_maximumEntrySize = response.size(),
      .d_maxTTL = 86400,
      .d_minTTL = 1,
    };
    DNSDistPacketCache packetCache(settings);

    {
      uint32_t key = 0;
      boost::optional<Netmask> subnet;
      DNSQuestion dnsQuestion(ids, query);
      bool found = packetCache.get(dnsQuestion, 0, &key, subnet, dnssecOK);
      BOOST_CHECK_EQUAL(found, false);
      BOOST_CHECK(!subnet);

      packetCache.insert(key, subnet, *(getFlagsFromDNSHeader(dnsQuestion.getHeader().get())), dnssecOK, ids.qname, QType::A, QClass::IN, response, RCode::NoError, boost::none);
      found = packetCache.get(dnsQuestion, queryID, &key, subnet, dnssecOK, 0, true);
      BOOST_CHECK_EQUAL(found, true);
    }
  }
}

const DNSDistPacketCache::CacheSettings s_localCacheSettings{
  .d_maxEntries = 500000,
};
static DNSDistPacketCache s_localCache(s_localCacheSettings);

static void threadMangler(unsigned int offset)
{
  InternalQueryState ids;
  ids.qtype = QType::A;
  ids.qclass = QClass::IN;
  ids.protocol = dnsdist::Protocol::DoUDP;

  try {
    ComboAddress remote;
    bool dnssecOK = false;
    for (unsigned int counter = 0; counter < 100000; ++counter) {
      ids.qname = DNSName("hello ") + DNSName(std::to_string(counter + offset));
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
      DNSQuestion dnsQuestion(ids, query);
      s_localCache.get(dnsQuestion, 0, &key, subnet, dnssecOK);

      s_localCache.insert(key, subnet, *(getFlagsFromDNSHeader(dnsQuestion.getHeader().get())), dnssecOK, ids.qname, QType::A, QClass::IN, response, 0, boost::none);
    }
  }
  catch (PDNSException& e) {
    cerr << "Had error: " << e.reason << endl;
    throw;
  }
}

static std::atomic<uint64_t> s_missing{0};

static void threadReader(unsigned int offset)
{
  InternalQueryState ids;
  ids.qtype = QType::A;
  ids.qclass = QClass::IN;
  ids.qname = DNSName("www.powerdns.com.");
  ids.protocol = dnsdist::Protocol::DoUDP;
  bool dnssecOK = false;
  try {
    ComboAddress remote;
    for (unsigned int counter = 0; counter < 100000; ++counter) {
      ids.qname = DNSName("hello ") + DNSName(std::to_string(counter + offset));
      PacketBuffer query;
      GenericDNSPacketWriter<PacketBuffer> pwQ(query, ids.qname, QType::A, QClass::IN, 0);
      pwQ.getHeader()->rd = 1;

      uint32_t key = 0;
      boost::optional<Netmask> subnet;
      DNSQuestion dnsQuestion(ids, query);
      bool found = s_localCache.get(dnsQuestion, 0, &key, subnet, dnssecOK);
      if (!found) {
        s_missing++;
      }
    }
  }
  catch (PDNSException& e) {
    cerr << "Had error in threadReader: " << e.reason << endl;
    throw;
  }
}

BOOST_AUTO_TEST_CASE(test_PacketCacheThreaded)
{
  try {
    std::vector<std::thread> threads;
    threads.reserve(4);
    for (int i = 0; i < 4; ++i) {
      threads.emplace_back(threadMangler, i * 1000000UL);
    }

    for (auto& thr : threads) {
      thr.join();
    }

    threads.clear();

    BOOST_CHECK_EQUAL(s_localCache.getSize() + s_localCache.getDeferredInserts() + s_localCache.getInsertCollisions(), 400000U);
    BOOST_CHECK_SMALL(1.0 * s_localCache.getInsertCollisions(), 10000.0);

    for (int i = 0; i < 4; ++i) {
      threads.emplace_back(threadReader, i * 1000000UL);
    }

    for (auto& thr : threads) {
      thr.join();
    }

    BOOST_CHECK((s_localCache.getDeferredInserts() + s_localCache.getDeferredLookups() + s_localCache.getInsertCollisions()) >= s_missing.load());
  }
  catch (const PDNSException& e) {
    cerr << "Had error: " << e.reason << endl;
    throw;
  }
}

BOOST_AUTO_TEST_CASE(test_PCCollision)
{
  const DNSDistPacketCache::CacheSettings settings{
    .d_maxEntries = 150000,
    .d_maxTTL = 86400,
    .d_minTTL = 1,
    .d_tempFailureTTL = 60,
    .d_maxNegativeTTL = 3600,
    .d_staleTTL = 60,
    .d_shardCount = 1,
    .d_dontAge = false,
    .d_deferrableInsertLock = true,
    .d_parseECS = true,
  };
  DNSDistPacketCache localCache(settings);
  BOOST_CHECK_EQUAL(localCache.getSize(), 0U);

  InternalQueryState ids;
  ids.qtype = QType::AAAA;
  ids.qclass = QClass::IN;
  ids.qname = DNSName("www.powerdns.com.");
  ids.protocol = dnsdist::Protocol::DoUDP;
  uint16_t qid = 0x42;
  uint32_t key{};
  uint32_t secondKey{};
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
    opt.setSource(Netmask("10.0.59.220/32"));
    ednsOptions.emplace_back(EDNSOptionCode::ECS, opt.makeOptString());
    pwQ.addOpt(512, 0, 0, ednsOptions);
    pwQ.commit();

    ComboAddress remote("192.0.2.1");
    ids.queryRealTime.start();
    DNSQuestion dnsQuestion(ids, query);
    bool found = localCache.get(dnsQuestion, 0, &key, subnetOut, dnssecOK);
    BOOST_CHECK_EQUAL(found, false);
    BOOST_REQUIRE(subnetOut);
    BOOST_CHECK_EQUAL(subnetOut->toString(), opt.getSource().toString());

    PacketBuffer response;
    GenericDNSPacketWriter<PacketBuffer> pwR(response, ids.qname, ids.qtype, QClass::IN, 0);
    pwR.getHeader()->rd = 1;
    pwR.getHeader()->id = qid;
    pwR.startRecord(ids.qname, ids.qtype, 100, QClass::IN, DNSResourceRecord::ANSWER);
    ComboAddress v6addr("::1");
    pwR.xfrCAWithoutPort(6, v6addr);
    pwR.commit();
    pwR.addOpt(512, 0, 0, ednsOptions);
    pwR.commit();

    localCache.insert(key, subnetOut, *(getFlagsFromDNSHeader(pwR.getHeader())), dnssecOK, ids.qname, ids.qtype, QClass::IN, response, RCode::NoError, boost::none);
    BOOST_CHECK_EQUAL(localCache.getSize(), 1U);

    found = localCache.get(dnsQuestion, 0, &key, subnetOut, dnssecOK);
    BOOST_CHECK_EQUAL(found, true);
    BOOST_REQUIRE(subnetOut);
    BOOST_CHECK_EQUAL(subnetOut->toString(), opt.getSource().toString());
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
    opt.setSource(Netmask("10.0.167.48/32"));
    ednsOptions.emplace_back(EDNSOptionCode::ECS, opt.makeOptString());
    pwQ.addOpt(512, 0, 0, ednsOptions);
    pwQ.commit();

    ComboAddress remote("192.0.2.1");
    ids.queryRealTime.start();
    DNSQuestion dnsQuestion(ids, query);
    subnetOut.reset();
    bool found = localCache.get(dnsQuestion, 0, &secondKey, subnetOut, dnssecOK);
    BOOST_CHECK_EQUAL(found, false);
    BOOST_CHECK_EQUAL(secondKey, key);
    BOOST_REQUIRE(subnetOut);
    BOOST_CHECK_EQUAL(subnetOut->toString(), opt.getSource().toString());
    BOOST_CHECK_EQUAL(localCache.getLookupCollisions(), 1U);
  }

#if 0
  /* to be able to compute a new collision if the packet cache hashing code is updated */
  {
    const DNSDistPacketCache::CacheSettings settings{
      .d_maxEntries = 10000,
    };
    DNSDistPacketCache pc(settings);
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
          opt.setSource(Netmask("10." + std::to_string(idxA) + "." + std::to_string(idxB) + "." + std::to_string(idxC) + "/32"));
          ednsOptions.clear();
          ednsOptions.emplace_back(EDNSOptionCode::ECS, opt.makeOptString());
          pwFQ.addOpt(512, 0, 0, ednsOptions);
          pwFQ.commit();
          secondKey = pc.getKey(ids.qname.getStorage(), ids.qname.wirelength(), secondQuery);
          auto pair = colMap.emplace(secondKey, opt.getSource());
          total++;
          if (!pair.second) {
            collisions++;
            cerr<<"Collision between "<<colMap[secondKey].toString()<<" and "<<opt.getSource().toString()<<" for key "<<secondKey<<endl;
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

BOOST_AUTO_TEST_CASE(test_PCDNSSECCollision)
{
  const DNSDistPacketCache::CacheSettings settings{
    .d_maxEntries = 150000,
    .d_maxTTL = 86400,
    .d_minTTL = 1,
    .d_tempFailureTTL = 60,
    .d_maxNegativeTTL = 3600,
    .d_staleTTL = 60,
    .d_shardCount = 1,
    .d_dontAge = false,
    .d_deferrableInsertLock = true,
    .d_parseECS = true,
  };
  DNSDistPacketCache localCache(settings);
  BOOST_CHECK_EQUAL(localCache.getSize(), 0U);

  InternalQueryState ids;
  ids.qtype = QType::AAAA;
  ids.qclass = QClass::IN;
  ids.qname = DNSName("www.powerdns.com.");
  ids.protocol = dnsdist::Protocol::DoUDP;
  uint16_t qid = 0x42;
  uint32_t key{};
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
    DNSQuestion dnsQuestion(ids, query);
    bool found = localCache.get(dnsQuestion, 0, &key, subnetOut, true);
    BOOST_CHECK_EQUAL(found, false);

    PacketBuffer response;
    GenericDNSPacketWriter<PacketBuffer> pwR(response, ids.qname, ids.qtype, QClass::IN, 0);
    pwR.getHeader()->rd = 1;
    pwR.getHeader()->id = qid;
    pwR.startRecord(ids.qname, ids.qtype, 100, QClass::IN, DNSResourceRecord::ANSWER);
    ComboAddress v6addr("::1");
    pwR.xfrCAWithoutPort(6, v6addr);
    pwR.commit();
    pwR.addOpt(512, 0, EDNS_HEADER_FLAG_DO);
    pwR.commit();

    localCache.insert(key, subnetOut, *(getFlagsFromDNSHeader(pwR.getHeader())), /* DNSSEC OK is set */ true, ids.qname, ids.qtype, QClass::IN, response, RCode::NoError, boost::none);
    BOOST_CHECK_EQUAL(localCache.getSize(), 1U);

    found = localCache.get(dnsQuestion, 0, &key, subnetOut, false);
    BOOST_CHECK_EQUAL(found, false);

    found = localCache.get(dnsQuestion, 0, &key, subnetOut, true);
    BOOST_CHECK_EQUAL(found, true);
  }
}

BOOST_AUTO_TEST_CASE(test_PacketCacheInspection)
{
  const DNSDistPacketCache::CacheSettings settings{
    .d_maxEntries = 150000,
    .d_maxTTL = 86400,
    .d_minTTL = 1,
  };
  DNSDistPacketCache localCache(settings);
  BOOST_CHECK_EQUAL(localCache.getSize(), 0U);

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

    localCache.insert(key++, boost::none, *getFlagsFromDNSHeader(pwQ.getHeader()), dnssecOK, qname, QType::A, QClass::IN, response, 0, boost::none);
    BOOST_CHECK_EQUAL(localCache.getSize(), key);
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

    localCache.insert(key++, boost::none, *getFlagsFromDNSHeader(pwQ.getHeader()), dnssecOK, qname, QType::A, QClass::IN, response, 0, boost::none);
    BOOST_CHECK_EQUAL(localCache.getSize(), key);
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

    localCache.insert(key++, boost::none, *getFlagsFromDNSHeader(pwQ.getHeader()), dnssecOK, qname, QType::A, QClass::IN, response, 0, boost::none);
    BOOST_CHECK_EQUAL(localCache.getSize(), key);
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

    localCache.insert(key++, boost::none, *getFlagsFromDNSHeader(pwQ.getHeader()), dnssecOK, qname, QType::A, QClass::IN, response, 0, boost::none);
    BOOST_CHECK_EQUAL(localCache.getSize(), key);
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

    localCache.insert(key++, boost::none, *getFlagsFromDNSHeader(pwQ.getHeader()), dnssecOK, qname, QType::A, QClass::IN, response, 0, boost::none);
    BOOST_CHECK_EQUAL(localCache.getSize(), key);
  }

  {
    auto domains = localCache.getDomainsContainingRecords(ComboAddress("192.0.2.1"));
    BOOST_CHECK_EQUAL(domains.size(), 2U);
    BOOST_CHECK_EQUAL(domains.count(DNSName("powerdns.com")), 1U);
    BOOST_CHECK_EQUAL(domains.count(DNSName("powerdns4.com")), 1U);
  }
  {
    auto domains = localCache.getDomainsContainingRecords(ComboAddress("192.0.2.2"));
    BOOST_CHECK_EQUAL(domains.size(), 1U);
    BOOST_CHECK_EQUAL(domains.count(DNSName("powerdns.com")), 1U);
  }
  {
    auto domains = localCache.getDomainsContainingRecords(ComboAddress("192.0.2.3"));
    BOOST_CHECK_EQUAL(domains.size(), 1U);
    BOOST_CHECK_EQUAL(domains.count(DNSName("powerdns1.com")), 1U);
  }
  {
    auto domains = localCache.getDomainsContainingRecords(ComboAddress("192.0.2.4"));
    BOOST_CHECK_EQUAL(domains.size(), 1U);
    BOOST_CHECK_EQUAL(domains.count(DNSName("powerdns1.com")), 1U);
  }
  {
    auto domains = localCache.getDomainsContainingRecords(ComboAddress("192.0.2.5"));
    BOOST_CHECK_EQUAL(domains.size(), 0U);
  }
  {
    auto domains = localCache.getDomainsContainingRecords(ComboAddress("2001:db8::3"));
    BOOST_CHECK_EQUAL(domains.size(), 1U);
    BOOST_CHECK_EQUAL(domains.count(DNSName("powerdns1.com")), 1U);
  }
  {
    auto domains = localCache.getDomainsContainingRecords(ComboAddress("2001:db8::4"));
    BOOST_CHECK_EQUAL(domains.size(), 2U);
    BOOST_CHECK_EQUAL(domains.count(DNSName("powerdns1.com")), 1U);
    BOOST_CHECK_EQUAL(domains.count(DNSName("powerdns3.com")), 1U);
  }
  {
    auto domains = localCache.getDomainsContainingRecords(ComboAddress("2001:db8::5"));
    BOOST_CHECK_EQUAL(domains.size(), 1U);
    BOOST_CHECK_EQUAL(domains.count(DNSName("powerdns3.com")), 1U);
  }

  {
    auto records = localCache.getRecordsForDomain(DNSName("powerdns.com"));
    BOOST_CHECK_EQUAL(records.size(), 2U);
    BOOST_CHECK_EQUAL(records.count(ComboAddress("192.0.2.1")), 1U);
    BOOST_CHECK_EQUAL(records.count(ComboAddress("192.0.2.2")), 1U);
  }

  {
    auto records = localCache.getRecordsForDomain(DNSName("powerdns1.com"));
    BOOST_CHECK_EQUAL(records.size(), 4U);
    BOOST_CHECK_EQUAL(records.count(ComboAddress("192.0.2.3")), 1U);
    BOOST_CHECK_EQUAL(records.count(ComboAddress("192.0.2.4")), 1U);
    BOOST_CHECK_EQUAL(records.count(ComboAddress("2001:db8::3")), 1U);
    BOOST_CHECK_EQUAL(records.count(ComboAddress("2001:db8::4")), 1U);
  }

  {
    auto records = localCache.getRecordsForDomain(DNSName("powerdns2.com"));
    BOOST_CHECK_EQUAL(records.size(), 0U);
  }

  {
    auto records = localCache.getRecordsForDomain(DNSName("powerdns3.com"));
    BOOST_CHECK_EQUAL(records.size(), 2U);
    BOOST_CHECK_EQUAL(records.count(ComboAddress("2001:db8::4")), 1U);
    BOOST_CHECK_EQUAL(records.count(ComboAddress("2001:db8::4")), 1U);
  }

  {
    auto records = localCache.getRecordsForDomain(DNSName("powerdns4.com"));
    BOOST_CHECK_EQUAL(records.size(), 1U);
    BOOST_CHECK_EQUAL(records.count(ComboAddress("192.0.2.1")), 1U);
  }

  {
    auto records = localCache.getRecordsForDomain(DNSName("powerdns5.com"));
    BOOST_CHECK_EQUAL(records.size(), 0U);
  }
}

BOOST_AUTO_TEST_CASE(test_PacketCacheXFR)
{
  const DNSDistPacketCache::CacheSettings settings{
    .d_maxEntries = 150000,
    .d_maxTTL = 86400,
    .d_minTTL = 1,
  };
  DNSDistPacketCache localCache(settings);
  BOOST_CHECK_EQUAL(localCache.getSize(), 0U);

  const std::set<QType> xfrTypes = {QType::AXFR, QType::IXFR};
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
    DNSQuestion dnsQuestion(ids, query);
    bool found = localCache.get(dnsQuestion, 0, &key, subnet, dnssecOK);
    BOOST_CHECK_EQUAL(found, false);
    BOOST_CHECK(!subnet);

    localCache.insert(key, subnet, *(getFlagsFromDNSHeader(dnsQuestion.getHeader().get())), dnssecOK, ids.qname, ids.qtype, ids.qclass, response, 0, boost::none);
    found = localCache.get(dnsQuestion, pwR.getHeader()->id, &key, subnet, dnssecOK, 0, true);
    BOOST_CHECK_EQUAL(found, false);
  }
}

BOOST_AUTO_TEST_SUITE_END()
