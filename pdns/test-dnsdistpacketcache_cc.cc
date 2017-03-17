#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN

#include <boost/test/unit_test.hpp>

#include "dnsdist.hh"
#include "iputils.hh"
#include "dnswriter.hh"
#include "dnsdist-cache.hh"

BOOST_AUTO_TEST_SUITE(dnsdistpacketcache_cc)

BOOST_AUTO_TEST_CASE(test_PacketCacheSimple) {
  const size_t maxEntries = 150000;
  DNSDistPacketCache PC(maxEntries, 86400, 1);
  BOOST_CHECK_EQUAL(PC.getSize(), 0);

  size_t counter=0;
  size_t skipped=0;
  ComboAddress remote;
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
      pwR.startRecord(a, QType::A, 100, QClass::IN, DNSResourceRecord::ANSWER);
      pwR.xfr32BitInt(0x01020304);
      pwR.commit();
      uint16_t responseLen = response.size();

      char responseBuf[4096];
      uint16_t responseBufSize = sizeof(responseBuf);
      uint32_t key = 0;
      DNSQuestion dq(&a, QType::A, QClass::IN, &remote, &remote, (struct dnsheader*) query.data(), query.size(), query.size(), false);
      bool found = PC.get(dq, a.wirelength(), 0, responseBuf, &responseBufSize, &key);
      BOOST_CHECK_EQUAL(found, false);

      PC.insert(key, a, QType::A, QClass::IN, (const char*) response.data(), responseLen, false, 0);

      found = PC.get(dq, a.wirelength(), pwR.getHeader()->id, responseBuf, &responseBufSize, &key, 0, true);
      if (found == true) {
        BOOST_CHECK_EQUAL(responseBufSize, responseLen);
        int match = memcmp(responseBuf, response.data(), responseLen);
        BOOST_CHECK_EQUAL(match, 0);
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
      DNSQuestion dq(&a, QType::A, QClass::IN, &remote, &remote, (struct dnsheader*) query.data(), query.size(), query.size(), false);
      bool found = PC.get(dq, a.wirelength(), 0, responseBuf, &responseBufSize, &key);
      if (found == true) {
        PC.expungeByName(a);
        deleted++;
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
      char response[4096];
      uint16_t responseSize = sizeof(response);
      DNSQuestion dq(&a, QType::A, QClass::IN, &remote, &remote, (struct dnsheader*) query.data(), len, query.size(), false);
      if(PC.get(dq, a.wirelength(), pwQ.getHeader()->id, response, &responseSize, &key)) {
        matches++;
      }
    }
    BOOST_CHECK_EQUAL(matches, expected);

    PC.expungeByName(DNSName(" hello"), QType::ANY, true);
    BOOST_CHECK_EQUAL(PC.getSize(), 0);
  }
  catch(PDNSException& e) {
    cerr<<"Had error: "<<e.reason<<endl;
    throw;
  }
}

static DNSDistPacketCache PC(500000);

static void *threadMangler(void* off)
{
  try {
    ComboAddress remote;
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
      DNSQuestion dq(&a, QType::A, QClass::IN, &remote, &remote, (struct dnsheader*) query.data(), query.size(), query.size(), false);
      PC.get(dq, a.wirelength(), 0, responseBuf, &responseBufSize, &key);

      PC.insert(key, a, QType::A, QClass::IN, (const char*) response.data(), responseLen, false, 0);
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
      DNSQuestion dq(&a, QType::A, QClass::IN, &remote, &remote, (struct dnsheader*) query.data(), query.size(), query.size(), false);
      bool found = PC.get(dq, a.wirelength(), 0, responseBuf, &responseBufSize, &key);
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

    BOOST_CHECK_EQUAL(PC.getSize() + PC.getDeferredInserts() + PC.getInsertCollisions(), 400000);
    BOOST_CHECK_SMALL(1.0*PC.getInsertCollisions(), 10000.0);

    for(int i=0; i < 4; ++i)
      pthread_create(&tid[i], 0, threadReader, (void*)(i*1000000UL));
    for(int i=0; i < 4 ; ++i)
      pthread_join(tid[i], &res);

    BOOST_CHECK((PC.getDeferredInserts() + PC.getDeferredLookups() + PC.getInsertCollisions()) >= g_missing);
  }
  catch(PDNSException& e) {
    cerr<<"Had error: "<<e.reason<<endl;
    throw;
  }

}

BOOST_AUTO_TEST_SUITE_END()
