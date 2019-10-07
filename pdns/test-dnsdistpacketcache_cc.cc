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
  try {
    for(counter = 0; counter < 100000; ++counter) {
      DNSName a=DNSName(std::to_string(counter))+DNSName(" hello");
      BOOST_CHECK_EQUAL(DNSName(a.toString()), a);

      vector<uint8_t> query;
      DNSPacketWriter pwQ(query, a, QType::A, QClass::IN, 0);
      pwQ.getHeader()->rd = 1;

      vector<uint8_t> response;
      DNSPacketWriter pwR(response, a, QType::A, QClass::IN, 0);
      pwR.getHeader()->rd = 1;
      pwR.getHeader()->ra = 1;
      pwR.getHeader()->qr = 1;
      pwR.getHeader()->id = pwQ.getHeader()->id;
      pwR.startRecord(a, QType::A, 7200, QClass::IN, DNSResourceRecord::ANSWER);
      pwR.xfr32BitInt(0x01020304);
      pwR.commit();
      uint16_t responseLen = response.size();

      char responseBuf[4096];
      uint16_t responseBufSize = sizeof(responseBuf);
      uint32_t key = 0;
      boost::optional<Netmask> subnet;
      auto dh = reinterpret_cast<dnsheader*>(query.data());
      DNSQuestion dq(&a, QType::A, QClass::IN, 0, &remote, &remote, dh, query.size(), query.size(), false, &queryTime);
      bool found = PC.get(dq, a.wirelength(), 0, responseBuf, &responseBufSize, &key, subnet, dnssecOK);
      BOOST_CHECK_EQUAL(found, false);
      BOOST_CHECK(!subnet);

      PC.insert(key, subnet, *(getFlagsFromDNSHeader(dh)), dnssecOK, a, QType::A, QClass::IN, (const char*) response.data(), responseLen, false, 0, boost::none);

      found = PC.get(dq, a.wirelength(), pwR.getHeader()->id, responseBuf, &responseBufSize, &key, subnet, dnssecOK, 0, true);
      if (found == true) {
        BOOST_CHECK_EQUAL(responseBufSize, responseLen);
        int match = memcmp(responseBuf, response.data(), responseLen);
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
    for(delcounter=0; delcounter < counter/1000; ++delcounter) {
      DNSName a=DNSName(std::to_string(delcounter))+DNSName(" hello");
      vector<uint8_t> query;
      DNSPacketWriter pwQ(query, a, QType::A, QClass::IN, 0);
      pwQ.getHeader()->rd = 1;
      char responseBuf[4096];
      uint16_t responseBufSize = sizeof(responseBuf);
      uint32_t key = 0;
      boost::optional<Netmask> subnet;
      DNSQuestion dq(&a, QType::A, QClass::IN, 0, &remote, &remote, (struct dnsheader*) query.data(), query.size(), query.size(), false, &queryTime);
      bool found = PC.get(dq, a.wirelength(), 0, responseBuf, &responseBufSize, &key, subnet, dnssecOK);
      if (found == true) {
        auto removed = PC.expungeByName(a);
        BOOST_CHECK_EQUAL(removed, 1U);
        deleted += removed;
      }
    }
    BOOST_CHECK_EQUAL(PC.getSize(), counter - skipped - deleted);

    size_t matches=0;
    vector<DNSResourceRecord> entry;
    size_t expected=counter-skipped-deleted;
    for(; delcounter < counter; ++delcounter) {
      DNSName a(DNSName(std::to_string(delcounter))+DNSName(" hello"));
      vector<uint8_t> query;
      DNSPacketWriter pwQ(query, a, QType::A, QClass::IN, 0);
      pwQ.getHeader()->rd = 1;
      uint16_t len = query.size();
      uint32_t key = 0;
      boost::optional<Netmask> subnet;
      char response[4096];
      uint16_t responseSize = sizeof(response);
      DNSQuestion dq(&a, QType::A, QClass::IN, 0, &remote, &remote, (struct dnsheader*) query.data(), len, query.size(), false, &queryTime);
      if(PC.get(dq, a.wirelength(), pwQ.getHeader()->id, response, &responseSize, &key, subnet, dnssecOK)) {
        matches++;
      }
    }

    /* in the unlikely event that the test took so long that the entries did expire.. */
    auto expired = PC.purgeExpired();
    BOOST_CHECK_EQUAL(matches + expired, expected);

    auto remaining = PC.getSize();
    auto removed = PC.expungeByName(DNSName(" hello"), QType::ANY, true);
    BOOST_CHECK_EQUAL(PC.getSize(), 0U);
    BOOST_CHECK_EQUAL(removed, remaining);
  }
  catch(PDNSException& e) {
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

    vector<uint8_t> query;
    DNSPacketWriter pwQ(query, a, QType::A, QClass::IN, 0);
    pwQ.getHeader()->rd = 1;

    vector<uint8_t> response;
    DNSPacketWriter pwR(response, a, QType::A, QClass::IN, 0);
    pwR.getHeader()->rd = 1;
    pwR.getHeader()->ra = 0;
    pwR.getHeader()->qr = 1;
    pwR.getHeader()->rcode = RCode::ServFail;
    pwR.getHeader()->id = pwQ.getHeader()->id;
    pwR.commit();
    uint16_t responseLen = response.size();

    char responseBuf[4096];
    uint16_t responseBufSize = sizeof(responseBuf);
    uint32_t key = 0;
    boost::optional<Netmask> subnet;
    auto dh = reinterpret_cast<dnsheader*>(query.data());
    DNSQuestion dq(&a, QType::A, QClass::IN, 0, &remote, &remote, dh, query.size(), query.size(), false, &queryTime);
    bool found = PC.get(dq, a.wirelength(), 0, responseBuf, &responseBufSize, &key, subnet, dnssecOK);
    BOOST_CHECK_EQUAL(found, false);
    BOOST_CHECK(!subnet);

    // Insert with failure-TTL of 0 (-> should not enter cache).
    PC.insert(key, subnet, *(getFlagsFromDNSHeader(dh)), dnssecOK, a, QType::A, QClass::IN, (const char*) response.data(), responseLen, false, RCode::ServFail, boost::optional<uint32_t>(0));
    found = PC.get(dq, a.wirelength(), pwR.getHeader()->id, responseBuf, &responseBufSize, &key, subnet, dnssecOK, 0, true);
    BOOST_CHECK_EQUAL(found, false);
    BOOST_CHECK(!subnet);

    // Insert with failure-TTL non-zero (-> should enter cache).
    PC.insert(key, subnet, *(getFlagsFromDNSHeader(dh)), dnssecOK, a, QType::A, QClass::IN, (const char*) response.data(), responseLen, false, RCode::ServFail, boost::optional<uint32_t>(300));
    found = PC.get(dq, a.wirelength(), pwR.getHeader()->id, responseBuf, &responseBufSize, &key, subnet, dnssecOK, 0, true);
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
    vector<uint8_t> query;
    DNSPacketWriter pwQ(query, name, QType::A, QClass::IN, 0);
    pwQ.getHeader()->rd = 1;

    vector<uint8_t> response;
    DNSPacketWriter pwR(response, name, QType::A, QClass::IN, 0);
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

    uint16_t responseLen = response.size();

    char responseBuf[4096];
    uint16_t responseBufSize = sizeof(responseBuf);
    uint32_t key = 0;
    boost::optional<Netmask> subnet;
    auto dh = reinterpret_cast<dnsheader*>(query.data());
    DNSQuestion dq(&name, QType::A, QClass::IN, 0, &remote, &remote, dh, query.size(), query.size(), false, &queryTime);
    bool found = PC.get(dq, name.wirelength(), 0, responseBuf, &responseBufSize, &key, subnet, dnssecOK);
    BOOST_CHECK_EQUAL(found, false);
    BOOST_CHECK(!subnet);

    PC.insert(key, subnet, *(getFlagsFromDNSHeader(dh)), dnssecOK, name, QType::A, QClass::IN, reinterpret_cast<const char*>(response.data()), responseLen, false, RCode::NoError, boost::none);
    found = PC.get(dq, name.wirelength(), pwR.getHeader()->id, responseBuf, &responseBufSize, &key, subnet, dnssecOK, 0, true);
    BOOST_CHECK_EQUAL(found, true);
    BOOST_CHECK(!subnet);

    sleep(2);
    /* it should have expired by now */
    found = PC.get(dq, name.wirelength(), pwR.getHeader()->id, responseBuf, &responseBufSize, &key, subnet, dnssecOK, 0, true);
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
    vector<uint8_t> query;
    DNSPacketWriter pwQ(query, name, QType::A, QClass::IN, 0);
    pwQ.getHeader()->rd = 1;

    vector<uint8_t> response;
    DNSPacketWriter pwR(response, name, QType::A, QClass::IN, 0);
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

    uint16_t responseLen = response.size();

    char responseBuf[4096];
    uint16_t responseBufSize = sizeof(responseBuf);
    uint32_t key = 0;
    boost::optional<Netmask> subnet;
    auto dh = reinterpret_cast<dnsheader*>(query.data());
    DNSQuestion dq(&name, QType::A, QClass::IN, 0, &remote, &remote, dh, query.size(), query.size(), false, &queryTime);
    bool found = PC.get(dq, name.wirelength(), 0, responseBuf, &responseBufSize, &key, subnet, dnssecOK);
    BOOST_CHECK_EQUAL(found, false);
    BOOST_CHECK(!subnet);

    PC.insert(key, subnet, *(getFlagsFromDNSHeader(dh)), dnssecOK, name, QType::A, QClass::IN, reinterpret_cast<const char*>(response.data()), responseLen, false, RCode::NXDomain, boost::none);
    found = PC.get(dq, name.wirelength(), pwR.getHeader()->id, responseBuf, &responseBufSize, &key, subnet, dnssecOK, 0, true);
    BOOST_CHECK_EQUAL(found, true);
    BOOST_CHECK(!subnet);

    sleep(2);
    /* it should have expired by now */
    found = PC.get(dq, name.wirelength(), pwR.getHeader()->id, responseBuf, &responseBufSize, &key, subnet, dnssecOK, 0, true);
    BOOST_CHECK_EQUAL(found, false);
    BOOST_CHECK(!subnet);
  }
  catch(const PDNSException& e) {
    cerr<<"Had error: "<<e.reason<<endl;
    throw;
  }
}

static DNSDistPacketCache g_PC(500000);

static void *threadMangler(void* off)
{
  struct timespec queryTime;
  gettime(&queryTime);  // does not have to be accurate ("realTime") in tests
  try {
    ComboAddress remote;
    bool dnssecOK = false;
    unsigned int offset=(unsigned int)(unsigned long)off;
    for(unsigned int counter=0; counter < 100000; ++counter) {
      DNSName a=DNSName("hello ")+DNSName(std::to_string(counter+offset));
      vector<uint8_t> query;
      DNSPacketWriter pwQ(query, a, QType::A, QClass::IN, 0);
      pwQ.getHeader()->rd = 1;

      vector<uint8_t> response;
      DNSPacketWriter pwR(response, a, QType::A, QClass::IN, 0);
      pwR.getHeader()->rd = 1;
      pwR.getHeader()->ra = 1;
      pwR.getHeader()->qr = 1;
      pwR.getHeader()->id = pwQ.getHeader()->id;
      pwR.startRecord(a, QType::A, 3600, QClass::IN, DNSResourceRecord::ANSWER);
      pwR.xfr32BitInt(0x01020304);
      pwR.commit();
      uint16_t responseLen = response.size();

      char responseBuf[4096];
      uint16_t responseBufSize = sizeof(responseBuf);
      uint32_t key = 0;
      boost::optional<Netmask> subnet;
      auto dh = reinterpret_cast<dnsheader*>(query.data());
      DNSQuestion dq(&a, QType::A, QClass::IN, 0, &remote, &remote, dh, query.size(), query.size(), false, &queryTime);
      g_PC.get(dq, a.wirelength(), 0, responseBuf, &responseBufSize, &key, subnet, dnssecOK);

      g_PC.insert(key, subnet, *(getFlagsFromDNSHeader(dh)), dnssecOK, a, QType::A, QClass::IN, (const char*) response.data(), responseLen, false, 0, boost::none);
    }
  }
  catch(PDNSException& e) {
    cerr<<"Had error: "<<e.reason<<endl;
    throw;
  }
  return 0;
}

AtomicCounter g_missing;

static void *threadReader(void* off)
{
  bool dnssecOK = false;
  struct timespec queryTime;
  gettime(&queryTime);  // does not have to be accurate ("realTime") in tests
  try
  {
    unsigned int offset=(unsigned int)(unsigned long)off;
    vector<DNSResourceRecord> entry;
    ComboAddress remote;
    for(unsigned int counter=0; counter < 100000; ++counter) {
      DNSName a=DNSName("hello ")+DNSName(std::to_string(counter+offset));
      vector<uint8_t> query;
      DNSPacketWriter pwQ(query, a, QType::A, QClass::IN, 0);
      pwQ.getHeader()->rd = 1;

      char responseBuf[4096];
      uint16_t responseBufSize = sizeof(responseBuf);
      uint32_t key = 0;
      boost::optional<Netmask> subnet;
      DNSQuestion dq(&a, QType::A, QClass::IN, 0, &remote, &remote, (struct dnsheader*) query.data(), query.size(), query.size(), false, &queryTime);
      bool found = g_PC.get(dq, a.wirelength(), 0, responseBuf, &responseBufSize, &key, subnet, dnssecOK);
      if (!found) {
	g_missing++;
      }
    }
  }
  catch(PDNSException& e) {
    cerr<<"Had error in threadReader: "<<e.reason<<endl;
    throw;
  }
  return 0;
}

BOOST_AUTO_TEST_CASE(test_PacketCacheThreaded) {
  try {
    pthread_t tid[4];
    for(int i=0; i < 4; ++i)
      pthread_create(&tid[i], 0, threadMangler, (void*)(i*1000000UL));
    void* res;
    for(int i=0; i < 4 ; ++i)
      pthread_join(tid[i], &res);

    BOOST_CHECK_EQUAL(g_PC.getSize() + g_PC.getDeferredInserts() + g_PC.getInsertCollisions(), 400000U);
    BOOST_CHECK_SMALL(1.0*g_PC.getInsertCollisions(), 10000.0);

    for(int i=0; i < 4; ++i)
      pthread_create(&tid[i], 0, threadReader, (void*)(i*1000000UL));
    for(int i=0; i < 4 ; ++i)
      pthread_join(tid[i], &res);

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

  /* lookup for a query with an ECS value of 10.0.118.46/32,
     insert a corresponding response */
  {
    vector<uint8_t> query;
    DNSPacketWriter pwQ(query, qname, qtype, QClass::IN, 0);
    pwQ.getHeader()->rd = 1;
    pwQ.getHeader()->id = qid;
    DNSPacketWriter::optvect_t ednsOptions;
    EDNSSubnetOpts opt;
    opt.source = Netmask("10.0.118.46/32");
    ednsOptions.push_back(std::make_pair(EDNSOptionCode::ECS, makeEDNSSubnetOptsString(opt)));
    pwQ.addOpt(512, 0, 0, ednsOptions);
    pwQ.commit();

    char responseBuf[4096];
    uint16_t responseBufSize = sizeof(responseBuf);
    ComboAddress remote("192.0.2.1");
    struct timespec queryTime;
    gettime(&queryTime);
    DNSQuestion dq(&qname, QType::AAAA, QClass::IN, 0, &remote, &remote, pwQ.getHeader(), query.size(), query.size(), false, &queryTime);
    bool found = PC.get(dq, qname.wirelength(), 0, responseBuf, &responseBufSize, &key, subnetOut, dnssecOK);
    BOOST_CHECK_EQUAL(found, false);
    BOOST_REQUIRE(subnetOut);
    BOOST_CHECK_EQUAL(subnetOut->toString(), opt.source.toString());

    vector<uint8_t> response;
    DNSPacketWriter pwR(response, qname, qtype, QClass::IN, 0);
    pwR.getHeader()->rd = 1;
    pwR.getHeader()->id = qid;
    pwR.startRecord(qname, qtype, 100, QClass::IN, DNSResourceRecord::ANSWER);
    ComboAddress v6("::1");
    pwR.xfrCAWithoutPort(6, v6);
    pwR.commit();
    pwR.addOpt(512, 0, 0, ednsOptions);
    pwR.commit();

    PC.insert(key, subnetOut, *(getFlagsFromDNSHeader(pwR.getHeader())), dnssecOK, qname, qtype, QClass::IN, reinterpret_cast<const char*>(response.data()), response.size(), false, RCode::NoError, boost::none);
    BOOST_CHECK_EQUAL(PC.getSize(), 1U);

    found = PC.get(dq, qname.wirelength(), 0, responseBuf, &responseBufSize, &key, subnetOut, dnssecOK);
    BOOST_CHECK_EQUAL(found, true);
    BOOST_REQUIRE(subnetOut);
    BOOST_CHECK_EQUAL(subnetOut->toString(), opt.source.toString());
  }

  /* now lookup for the same query with an ECS value of 10.0.123.193/32
     we should get the same key (collision) but no match */
  {
    vector<uint8_t> query;
    DNSPacketWriter pwQ(query, qname, qtype, QClass::IN, 0);
    pwQ.getHeader()->rd = 1;
    pwQ.getHeader()->id = qid;
    DNSPacketWriter::optvect_t ednsOptions;
    EDNSSubnetOpts opt;
    opt.source = Netmask("10.0.123.193/32");
    ednsOptions.push_back(std::make_pair(EDNSOptionCode::ECS, makeEDNSSubnetOptsString(opt)));
    pwQ.addOpt(512, 0, 0, ednsOptions);
    pwQ.commit();

    char responseBuf[4096];
    uint16_t responseBufSize = sizeof(responseBuf);
    ComboAddress remote("192.0.2.1");
    struct timespec queryTime;
    gettime(&queryTime);
    DNSQuestion dq(&qname, QType::AAAA, QClass::IN, 0, &remote, &remote, pwQ.getHeader(), query.size(), query.size(), false, &queryTime);
    bool found = PC.get(dq, qname.wirelength(), 0, responseBuf, &responseBufSize, &secondKey, subnetOut, dnssecOK);
    BOOST_CHECK_EQUAL(found, false);
    BOOST_CHECK_EQUAL(secondKey, key);
    BOOST_REQUIRE(subnetOut);
    BOOST_CHECK_EQUAL(subnetOut->toString(), opt.source.toString());
    BOOST_CHECK_EQUAL(PC.getLookupCollisions(), 1U);
  }
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
    vector<uint8_t> query;
    DNSPacketWriter pwQ(query, qname, qtype, QClass::IN, 0);
    pwQ.getHeader()->rd = 1;
    pwQ.getHeader()->id = qid;
    pwQ.addOpt(512, 0, EDNS_HEADER_FLAG_DO);
    pwQ.commit();

    char responseBuf[4096];
    uint16_t responseBufSize = sizeof(responseBuf);
    ComboAddress remote("192.0.2.1");
    struct timespec queryTime;
    gettime(&queryTime);
    DNSQuestion dq(&qname, QType::AAAA, QClass::IN, 0, &remote, &remote, pwQ.getHeader(), query.size(), query.size(), false, &queryTime);
    bool found = PC.get(dq, qname.wirelength(), 0, responseBuf, &responseBufSize, &key, subnetOut, true);
    BOOST_CHECK_EQUAL(found, false);

    vector<uint8_t> response;
    DNSPacketWriter pwR(response, qname, qtype, QClass::IN, 0);
    pwR.getHeader()->rd = 1;
    pwR.getHeader()->id = qid;
    pwR.startRecord(qname, qtype, 100, QClass::IN, DNSResourceRecord::ANSWER);
    ComboAddress v6("::1");
    pwR.xfrCAWithoutPort(6, v6);
    pwR.commit();
    pwR.addOpt(512, 0, EDNS_HEADER_FLAG_DO);
    pwR.commit();

    PC.insert(key, subnetOut, *(getFlagsFromDNSHeader(pwR.getHeader())), /* DNSSEC OK is set */ true, qname, qtype, QClass::IN, reinterpret_cast<const char*>(response.data()), response.size(), false, RCode::NoError, boost::none);
    BOOST_CHECK_EQUAL(PC.getSize(), 1U);

    found = PC.get(dq, qname.wirelength(), 0, responseBuf, &responseBufSize, &key, subnetOut, false);
    BOOST_CHECK_EQUAL(found, false);

    found = PC.get(dq, qname.wirelength(), 0, responseBuf, &responseBufSize, &key, subnetOut, true);
    BOOST_CHECK_EQUAL(found, true);
  }

}

BOOST_AUTO_TEST_SUITE_END()
