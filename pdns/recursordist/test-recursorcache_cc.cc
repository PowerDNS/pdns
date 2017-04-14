#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <boost/test/unit_test.hpp>
#include <boost/test/floating_point_comparison.hpp>

#include "iputils.hh"
#include "recursor_cache.hh"

BOOST_AUTO_TEST_SUITE(recursorcache_cc)

BOOST_AUTO_TEST_CASE(test_RecursorCacheSimple) {
  MemRecursorCache MRC;

  std::vector<DNSRecord> records;
  std::vector<std::shared_ptr<RRSIGRecordContent>> signatures;
  time_t now = time(nullptr);

  BOOST_CHECK_EQUAL(MRC.size(), 0);
  MRC.replace(now, DNSName("hello"), QType(QType::A), records, signatures, true, boost::none);
  BOOST_CHECK_EQUAL(MRC.size(), 1);
  BOOST_CHECK_GT(MRC.bytes(), 1);
  BOOST_CHECK_EQUAL(MRC.doWipeCache(DNSName("hello"), false, QType::A), 1);
  BOOST_CHECK_EQUAL(MRC.size(), 0);
  BOOST_CHECK_EQUAL(MRC.bytes(), 0);

  uint64_t counter = 0;
  try {
    for(counter = 0; counter < 100000; ++counter) {
      DNSName a = DNSName("hello ")+DNSName(std::to_string(counter));
      BOOST_CHECK_EQUAL(DNSName(a.toString()), a);

      MRC.replace(now, a, QType(QType::A), records, signatures, true, boost::none);
      if(!MRC.doWipeCache(a, false))
	BOOST_FAIL("Could not remove entry we just added to the cache!");
      MRC.replace(now, a, QType(QType::A), records, signatures, true, boost::none);
    }

    BOOST_CHECK_EQUAL(MRC.size(), counter);

    uint64_t delcounter = 0;
    for(delcounter=0; delcounter < counter/100; ++delcounter) {
      DNSName a = DNSName("hello ")+DNSName(std::to_string(delcounter));
      BOOST_CHECK_EQUAL(MRC.doWipeCache(a, false, QType::A), 1);
    }

    BOOST_CHECK_EQUAL(MRC.size(), counter-delcounter);

    std::vector<DNSRecord> retrieved;
    ComboAddress who("192.0.2.1");
    uint64_t matches = 0;
    int64_t expected = counter-delcounter;

    for(; delcounter < counter; ++delcounter) {
      if(MRC.get(now, DNSName("hello ")+DNSName(std::to_string(delcounter)), QType(QType::A), false, &retrieved, who, nullptr)) {
	matches++;
      }
    }
    BOOST_CHECK_EQUAL(matches, expected);
    BOOST_CHECK_EQUAL(retrieved.size(), records.size());

    MRC.doWipeCache(DNSName("."), true);
    BOOST_CHECK_EQUAL(MRC.size(), 0);

    time_t ttd = now + 30;
    DNSName power("powerdns.com.");
    DNSRecord dr1;
    ComboAddress dr1Content("2001:DB8::1");
    dr1.d_name = power;
    dr1.d_type = QType::AAAA;
    dr1.d_class = QClass::IN;
    dr1.d_content = std::make_shared<AAAARecordContent>(dr1Content);
    dr1.d_ttl = static_cast<uint32_t>(ttd);
    dr1.d_place = DNSResourceRecord::ANSWER;

    DNSRecord dr2;
    ComboAddress dr2Content("192.0.2.42");
    dr2.d_name = power;
    dr2.d_type = QType::A;
    dr2.d_class = QClass::IN;
    dr2.d_content = std::make_shared<ARecordContent>(dr2Content);
    dr2.d_ttl = static_cast<uint32_t>(ttd);
    // the place should not matter to the cache
    dr2.d_place = DNSResourceRecord::AUTHORITY;

    // insert a subnet specific entry
    records.push_back(dr1);
    MRC.replace(now, power, QType(QType::AAAA), records, signatures, true, boost::optional<Netmask>("192.0.2.1/25"));
    BOOST_CHECK_EQUAL(MRC.size(), 1);

    retrieved.clear();
    // subnet specific should be returned for a matching subnet
    BOOST_CHECK_EQUAL(MRC.get(now, power, QType(QType::AAAA), false, &retrieved, ComboAddress("192.0.2.2"), nullptr), (ttd-now));
    BOOST_REQUIRE_EQUAL(retrieved.size(), 1);
    BOOST_CHECK_EQUAL(getRR<AAAARecordContent>(retrieved.at(0))->getCA().toString(), dr1Content.toString());

    retrieved.clear();
    // subnet specific should not be returned for a different subnet
    BOOST_CHECK_LT(MRC.get(now, power, QType(QType::AAAA), false, &retrieved, ComboAddress("127.0.0.1"), nullptr), 0);
    BOOST_CHECK_EQUAL(retrieved.size(), 0);

    // remove everything
    MRC.doWipeCache(DNSName("."), true);
    BOOST_CHECK_EQUAL(MRC.size(), 0);

    // insert a NON-subnet specific entry
    records.clear();
    records.push_back(dr2);
    MRC.replace(now, power, QType(QType::A), records, signatures, true, boost::none);
    BOOST_CHECK_EQUAL(MRC.size(), 1);

    // NON-subnet specific should always be returned
    BOOST_CHECK_EQUAL(MRC.get(now, power, QType(QType::A), false, &retrieved, ComboAddress("127.0.0.1"), nullptr), (ttd-now));
    BOOST_REQUIRE_EQUAL(retrieved.size(), 1);
    BOOST_CHECK_EQUAL(getRR<ARecordContent>(retrieved.at(0))->getCA().toString(), dr2Content.toString());
    retrieved.clear();

    // insert a subnet specific entry for the same name but a different QType
    records.clear();
    records.push_back(dr1);
    MRC.replace(now, power, QType(QType::AAAA), records, signatures, true, boost::optional<Netmask>("192.0.2.1/25"));
    // we should not have replaced the existing entry
    BOOST_CHECK_EQUAL(MRC.size(), 2);

    // insert a TXT one, we will use that later
    records.clear();
    records.push_back(dr1);
    MRC.replace(now, power, QType(QType::TXT), records, signatures, true, boost::none);
    // we should not have replaced any existing entry
    BOOST_CHECK_EQUAL(MRC.size(), 3);

    // we should still get the NON-subnet specific entry
    BOOST_CHECK_EQUAL(MRC.get(now, power, QType(QType::A), false, &retrieved, ComboAddress("127.0.0.1"), nullptr), (ttd-now));
    BOOST_REQUIRE_EQUAL(retrieved.size(), 1);
    BOOST_CHECK_EQUAL(getRR<ARecordContent>(retrieved.at(0))->getCA().toString(), dr2Content.toString());
    retrieved.clear();

    // we should get the subnet specific entry if we are from the right subnet
    BOOST_CHECK_EQUAL(MRC.get(now, power, QType(QType::AAAA), false, &retrieved, ComboAddress("192.0.2.3"), nullptr), (ttd-now));
    BOOST_REQUIRE_EQUAL(retrieved.size(), 1);
    BOOST_CHECK_EQUAL(getRR<AAAARecordContent>(retrieved.at(0))->getCA().toString(), dr1Content.toString());
    retrieved.clear();

    // but nothing from a different subnet
    BOOST_CHECK_LT(MRC.get(now, power, QType(QType::AAAA), false, &retrieved, ComboAddress("127.0.0.1"), nullptr), 0);
    BOOST_CHECK_EQUAL(retrieved.size(), 0);
    retrieved.clear();

    // QType::ANY should return any qtype, so from the right subnet we should get all of them
    BOOST_CHECK_EQUAL(MRC.get(now, power, QType(QType::ANY), false, &retrieved, ComboAddress("192.0.2.3"), nullptr), (ttd-now));
    BOOST_CHECK_EQUAL(retrieved.size(), 3);
    for (const auto& rec : retrieved) {
      BOOST_CHECK(rec.d_type == QType::A || rec.d_type == QType::AAAA || rec.d_type == QType::TXT);
    }
    // check that the place is always set to ANSWER
    for (const auto& rec : retrieved) {
      BOOST_CHECK(rec.d_place == DNSResourceRecord::ANSWER);
    }
    retrieved.clear();

    // but only the non-subnet specific from the another subnet
    BOOST_CHECK_EQUAL(MRC.get(now, power, QType(QType::ANY), false, &retrieved, ComboAddress("127.0.0.1"), nullptr), (ttd-now));
    BOOST_CHECK_EQUAL(retrieved.size(), 2);
    for (const auto& rec : retrieved) {
      BOOST_CHECK(rec.d_type == QType::A || rec.d_type == QType::TXT);
    }
    retrieved.clear();

    // QType::ADDR should return both A and AAAA but no TXT, so two entries from the right subnet
    BOOST_CHECK_EQUAL(MRC.get(now, power, QType(QType::ADDR), false, &retrieved, ComboAddress("192.0.2.3"), nullptr), (ttd-now));
    BOOST_CHECK_EQUAL(retrieved.size(), 2);
    for (const auto& rec : retrieved) {
      BOOST_CHECK(rec.d_type == QType::A || rec.d_type == QType::AAAA);
    }
    retrieved.clear();

    // but only the non-subnet specific one from the another subnet
    BOOST_CHECK_EQUAL(MRC.get(now, power, QType(QType::ADDR), false, &retrieved, ComboAddress("127.0.0.1"), nullptr), (ttd-now));
    BOOST_REQUIRE_EQUAL(retrieved.size(), 1);
    BOOST_CHECK(retrieved.at(0).d_type == QType::A);
    retrieved.clear();

    // entries are only valid until ttd, we should not get anything after that because they are expired
    BOOST_CHECK_LT(MRC.get(ttd + 5, power, QType(QType::ADDR), false, &retrieved, ComboAddress("127.0.0.1"), nullptr), 0);
    BOOST_CHECK_EQUAL(retrieved.size(), 0);
    retrieved.clear();

    // let's age the records for our existing QType::TXT entry so they are now only valid for 5s
    uint32_t newTTL = 5;
    BOOST_CHECK_EQUAL(MRC.doAgeCache(now, power, QType::TXT, newTTL), true);

    // we should still be able to retrieve it
    BOOST_CHECK_EQUAL(MRC.get(now, power, QType(QType::TXT), false, &retrieved, ComboAddress("127.0.0.1"), nullptr), newTTL);
    BOOST_CHECK_EQUAL(retrieved.size(), 1);
    BOOST_CHECK(retrieved.at(0).d_type == QType::TXT);
    // please note that this is still a TTD at this point
    BOOST_CHECK_EQUAL(retrieved.at(0).d_ttl, now + newTTL);
    retrieved.clear();

    // but 10s later it should be gone
    BOOST_CHECK_LT(MRC.get(now + 10, power, QType(QType::TXT), false, &retrieved, ComboAddress("127.0.0.1"), nullptr), 0);
    BOOST_CHECK_EQUAL(retrieved.size(), 0);
    retrieved.clear();

    // wipe everything
    MRC.doWipeCache(DNSName("."), true);
    BOOST_CHECK_EQUAL(MRC.size(), 0);
    records.clear();

    // insert auth record
    records.push_back(dr2);
    MRC.replace(now, power, QType(QType::A), records, signatures, true, boost::none);
    BOOST_CHECK_EQUAL(MRC.size(), 1);
    BOOST_CHECK_EQUAL(MRC.get(now, power, QType(QType::A), false, &retrieved, ComboAddress("127.0.0.1"), nullptr), (ttd-now));
    BOOST_CHECK_EQUAL(retrieved.size(), 1);

    DNSRecord dr3;
    ComboAddress dr3Content("192.0.2.84");
    dr3.d_name = power;
    dr3.d_type = QType::A;
    dr3.d_class = QClass::IN;
    dr3.d_content = std::make_shared<ARecordContent>(dr3Content);
    dr3.d_ttl = static_cast<uint32_t>(ttd + 100);
    // the place should not matter to the cache
    dr3.d_place = DNSResourceRecord::AUTHORITY;

    // this is important for our tests
    BOOST_REQUIRE_GT(dr3.d_ttl, ttd);

    records.clear();
    records.push_back(dr3);

    // non-auth should not replace valid auth
    MRC.replace(now, power, QType(QType::A), records, signatures, false, boost::none);
    BOOST_CHECK_EQUAL(MRC.size(), 1);
    BOOST_CHECK_EQUAL(MRC.get(now, power, QType(QType::A), false, &retrieved, ComboAddress("127.0.0.1"), nullptr), (ttd-now));
    BOOST_REQUIRE_EQUAL(retrieved.size(), 1);
    BOOST_CHECK_EQUAL(getRR<ARecordContent>(retrieved.at(0))->getCA().toString(), dr2Content.toString());

    // but non-auth _should_ replace expired auth
    MRC.replace(ttd + 1, power, QType(QType::A), records, signatures, false, boost::none);
    BOOST_CHECK_EQUAL(MRC.size(), 1);
    BOOST_CHECK_EQUAL(MRC.get(ttd + 1, power, QType(QType::A), false, &retrieved, ComboAddress("127.0.0.1"), nullptr), (dr3.d_ttl - (ttd + 1)));
    BOOST_REQUIRE_EQUAL(retrieved.size(), 1);
    BOOST_CHECK_EQUAL(getRR<ARecordContent>(retrieved.at(0))->getCA().toString(), dr3Content.toString());

    // auth should replace non-auth
    records.clear();
    records.push_back(dr2);
    MRC.replace(now, power, QType(QType::A), records, signatures, false, boost::none);
    BOOST_CHECK_EQUAL(MRC.size(), 1);
    BOOST_CHECK_EQUAL(MRC.get(now, power, QType(QType::A), false, &retrieved, ComboAddress("127.0.0.1"), nullptr), (ttd-now));
    BOOST_REQUIRE_EQUAL(retrieved.size(), 1);
    BOOST_CHECK_EQUAL(getRR<ARecordContent>(retrieved.at(0))->getCA().toString(), dr2Content.toString());

  }
  catch(const PDNSException& e) {
    cerr<<"Had error: "<<e.reason<<endl;
    throw;
  }
}

BOOST_AUTO_TEST_SUITE_END()
