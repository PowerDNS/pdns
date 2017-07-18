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
  std::vector<std::shared_ptr<DNSRecord>> authRecords;
  std::vector<std::shared_ptr<RRSIGRecordContent>> signatures;
  time_t now = time(nullptr);

  BOOST_CHECK_EQUAL(MRC.size(), 0);
  MRC.replace(now, DNSName("hello"), QType(QType::A), records, signatures, authRecords, true, boost::none);
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

      MRC.replace(now, a, QType(QType::A), records, signatures, authRecords, true, boost::none);
      if(!MRC.doWipeCache(a, false))
	BOOST_FAIL("Could not remove entry we just added to the cache!");
      MRC.replace(now, a, QType(QType::A), records, signatures, authRecords, true, boost::none);
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
    MRC.replace(now, power, QType(QType::AAAA), records, signatures, authRecords, true, boost::optional<Netmask>("192.0.2.1/25"));
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
    MRC.replace(now, power, QType(QType::A), records, signatures, authRecords, true, boost::none);
    BOOST_CHECK_EQUAL(MRC.size(), 1);

    // NON-subnet specific should always be returned
    BOOST_CHECK_EQUAL(MRC.get(now, power, QType(QType::A), false, &retrieved, ComboAddress("127.0.0.1"), nullptr), (ttd-now));
    BOOST_REQUIRE_EQUAL(retrieved.size(), 1);
    BOOST_CHECK_EQUAL(getRR<ARecordContent>(retrieved.at(0))->getCA().toString(), dr2Content.toString());
    retrieved.clear();

    // insert a subnet specific entry for the same name but a different QType
    records.clear();
    records.push_back(dr1);
    MRC.replace(now, power, QType(QType::AAAA), records, signatures, authRecords, true, boost::optional<Netmask>("192.0.2.1/25"));
    // we should not have replaced the existing entry
    BOOST_CHECK_EQUAL(MRC.size(), 2);

    // insert a TXT one, we will use that later
    records.clear();
    records.push_back(dr1);
    MRC.replace(now, power, QType(QType::TXT), records, signatures, authRecords, true, boost::none);
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
    MRC.replace(now, power, QType(QType::A), records, signatures, authRecords, true, boost::none);
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
    MRC.replace(now, power, QType(QType::A), records, signatures, authRecords, false, boost::none);
    BOOST_CHECK_EQUAL(MRC.size(), 1);
    BOOST_CHECK_EQUAL(MRC.get(now, power, QType(QType::A), false, &retrieved, ComboAddress("127.0.0.1"), nullptr), (ttd-now));
    BOOST_REQUIRE_EQUAL(retrieved.size(), 1);
    BOOST_CHECK_EQUAL(getRR<ARecordContent>(retrieved.at(0))->getCA().toString(), dr2Content.toString());

    // but non-auth _should_ replace expired auth
    MRC.replace(ttd + 1, power, QType(QType::A), records, signatures, authRecords, false, boost::none);
    BOOST_CHECK_EQUAL(MRC.size(), 1);
    BOOST_CHECK_EQUAL(MRC.get(ttd + 1, power, QType(QType::A), false, &retrieved, ComboAddress("127.0.0.1"), nullptr), (dr3.d_ttl - (ttd + 1)));
    BOOST_REQUIRE_EQUAL(retrieved.size(), 1);
    BOOST_CHECK_EQUAL(getRR<ARecordContent>(retrieved.at(0))->getCA().toString(), dr3Content.toString());

    // auth should replace non-auth
    records.clear();
    records.push_back(dr2);
    MRC.replace(now, power, QType(QType::A), records, signatures, authRecords, false, boost::none);
    BOOST_CHECK_EQUAL(MRC.size(), 1);
    BOOST_CHECK_EQUAL(MRC.get(now, power, QType(QType::A), false, &retrieved, ComboAddress("127.0.0.1"), nullptr), (ttd-now));
    BOOST_REQUIRE_EQUAL(retrieved.size(), 1);
    BOOST_CHECK_EQUAL(getRR<ARecordContent>(retrieved.at(0))->getCA().toString(), dr2Content.toString());

    // Most specific netmask test
    // wipe everything
    MRC.doWipeCache(DNSName("."), true);
    BOOST_CHECK_EQUAL(MRC.size(), 0);
    records.clear();

    // insert an entry for 192.0.0.1/8
    records.clear();
    records.push_back(dr2);
    MRC.replace(now, power, QType(QType::A), records, signatures, authRecords, true, boost::optional<Netmask>("192.0.0.1/8"));
    BOOST_CHECK_EQUAL(MRC.size(), 1);

    /* same as dr2 except for the actual IP */
    DNSRecord dr4;
    ComboAddress dr4Content("192.0.2.126");
    dr4.d_name = power;
    dr4.d_type = QType::A;
    dr4.d_class = QClass::IN;
    dr4.d_content = std::make_shared<ARecordContent>(dr4Content);
    dr4.d_ttl = static_cast<uint32_t>(ttd);
    dr4.d_place = DNSResourceRecord::AUTHORITY;

    // insert an other entry but for 192.168.0.1/31
    records.clear();
    records.push_back(dr4);
    MRC.replace(now, power, QType(QType::A), records, signatures, authRecords, true, boost::optional<Netmask>("192.168.0.1/31"));
    // we should not have replaced any existing entry
    BOOST_CHECK_EQUAL(MRC.size(), 2);

    // insert the same than the first one but for 192.168.0.2/32
    records.clear();
    records.push_back(dr2);
    MRC.replace(now, power, QType(QType::A), records, signatures, authRecords, true, boost::optional<Netmask>("192.168.0.2/32"));
    // we should not have replaced any existing entry
    BOOST_CHECK_EQUAL(MRC.size(), 3);

    // we should get the most specific entry for 192.168.0.1, so the second one
    BOOST_CHECK_EQUAL(MRC.get(now, power, QType(QType::A), false, &retrieved, ComboAddress("192.168.0.1"), nullptr), (ttd-now));
    BOOST_REQUIRE_EQUAL(retrieved.size(), 1);
    BOOST_CHECK_EQUAL(getRR<ARecordContent>(retrieved.at(0))->getCA().toString(), dr4Content.toString());
    retrieved.clear();
  }
  catch(const PDNSException& e) {
    cerr<<"Had error: "<<e.reason<<endl;
    throw;
  }
}

BOOST_AUTO_TEST_CASE(test_RecursorCache_ExpungingExpiredEntries) {
  MemRecursorCache MRC;

  std::vector<DNSRecord> records;
  std::vector<std::shared_ptr<RRSIGRecordContent>> signatures;
  std::vector<std::shared_ptr<DNSRecord>> authRecs;
  BOOST_CHECK_EQUAL(MRC.size(), 0);
  time_t now = time(nullptr);
  DNSName power1("powerdns.com.");
  DNSName power2("powerdns-1.com.");
  time_t ttd = now - 30;
  std::vector<DNSRecord> retrieved;
  ComboAddress who("192.0.2.1");

  /* entry for power, which expired 30s ago */
  DNSRecord dr1;
  ComboAddress dr1Content("2001:DB8::1");
  dr1.d_name = power1;
  dr1.d_type = QType::AAAA;
  dr1.d_class = QClass::IN;
  dr1.d_content = std::make_shared<AAAARecordContent>(dr1Content);
  dr1.d_ttl = static_cast<uint32_t>(ttd);
  dr1.d_place = DNSResourceRecord::ANSWER;

  /* entry for power1, which expired 30 ago too */
  DNSRecord dr2;
  ComboAddress dr2Content("2001:DB8::2");
  dr2.d_name = power2;
  dr2.d_type = QType::AAAA;
  dr2.d_class = QClass::IN;
  dr2.d_content = std::make_shared<AAAARecordContent>(dr2Content);
  dr2.d_ttl = static_cast<uint32_t>(ttd);
  dr2.d_place = DNSResourceRecord::ANSWER;

  /* insert both entries */
  records.push_back(dr1);
  MRC.replace(now, power1, QType(dr1.d_type), records, signatures, authRecs, true, boost::none);
  records.clear();
  records.push_back(dr2);
  MRC.replace(now, power2, QType(dr2.d_type), records, signatures, authRecs, true, boost::none);
  records.clear();
  BOOST_CHECK_EQUAL(MRC.size(), 2);

  /* the one for power2 having been inserted
     more recently should be removed last */
  /* we ask that only entry remains in the cache */
  MRC.doPrune(1);
  BOOST_CHECK_EQUAL(MRC.size(), 1);

  /* the remaining entry should be power2, but to get it
     we need to go back in the past a bit */
  BOOST_CHECK_EQUAL(MRC.get(ttd - 1, power2, QType(dr2.d_type), false, &retrieved, who, nullptr), 1);
  BOOST_REQUIRE_EQUAL(retrieved.size(), 1);
  BOOST_CHECK_EQUAL(getRR<AAAARecordContent>(retrieved.at(0))->getCA().toString(), dr2Content.toString());
  /* check that power1 is gone */
  BOOST_CHECK_EQUAL(MRC.get(ttd - 1, power1, QType(dr1.d_type), false, &retrieved, who, nullptr), -1);

  /* clear everything up */
  MRC.doWipeCache(DNSName("."), true);
  BOOST_CHECK_EQUAL(MRC.size(), 0);
  records.clear();

  /* insert both entries back */
  records.push_back(dr1);
  MRC.replace(now, power1, QType(dr1.d_type), records, signatures, authRecs, true, boost::none);
  records.clear();
  records.push_back(dr2);
  MRC.replace(now, power2, QType(dr2.d_type), records, signatures, authRecs, true, boost::none);
  records.clear();
  BOOST_CHECK_EQUAL(MRC.size(), 2);

  /* trigger a miss (expired) for power2 */
  BOOST_CHECK_EQUAL(MRC.get(now, power2, QType(dr2.d_type), false, &retrieved, who, nullptr), -now);

  /* power2 should have been moved to the front of the expunge
     queue, and should this time be removed first */
  /* we ask that only entry remains in the cache */
  MRC.doPrune(1);
  BOOST_CHECK_EQUAL(MRC.size(), 1);

  /* the remaining entry should be power1, but to get it
     we need to go back in the past a bit */
  BOOST_CHECK_EQUAL(MRC.get(ttd - 1, power1, QType(dr1.d_type), false, &retrieved, who, nullptr), 1);
  BOOST_REQUIRE_EQUAL(retrieved.size(), 1);
  BOOST_CHECK_EQUAL(getRR<AAAARecordContent>(retrieved.at(0))->getCA().toString(), dr1Content.toString());
  /* check that power2 is gone */
  BOOST_CHECK_EQUAL(MRC.get(ttd - 1, power2, QType(dr2.d_type), false, &retrieved, who, nullptr), -1);
}

BOOST_AUTO_TEST_CASE(test_RecursorCache_ExpungingValidEntries) {
  MemRecursorCache MRC;

  std::vector<DNSRecord> records;
  std::vector<std::shared_ptr<RRSIGRecordContent>> signatures;
  std::vector<std::shared_ptr<DNSRecord>> authRecs;
  BOOST_CHECK_EQUAL(MRC.size(), 0);
  time_t now = time(nullptr);
  DNSName power1("powerdns.com.");
  DNSName power2("powerdns-1.com.");
  time_t ttd = now + 30;
  std::vector<DNSRecord> retrieved;
  ComboAddress who("192.0.2.1");

  /* entry for power, which will expire in 30s */
  DNSRecord dr1;
  ComboAddress dr1Content("2001:DB8::1");
  dr1.d_name = power1;
  dr1.d_type = QType::AAAA;
  dr1.d_class = QClass::IN;
  dr1.d_content = std::make_shared<AAAARecordContent>(dr1Content);
  dr1.d_ttl = static_cast<uint32_t>(ttd);
  dr1.d_place = DNSResourceRecord::ANSWER;

  /* entry for power1, which will expire in 30s too */
  DNSRecord dr2;
  ComboAddress dr2Content("2001:DB8::2");
  dr2.d_name = power2;
  dr2.d_type = QType::AAAA;
  dr2.d_class = QClass::IN;
  dr2.d_content = std::make_shared<AAAARecordContent>(dr2Content);
  dr2.d_ttl = static_cast<uint32_t>(ttd);
  dr2.d_place = DNSResourceRecord::ANSWER;

  /* insert both entries */
  records.push_back(dr1);
  MRC.replace(now, power1, QType(dr1.d_type), records, signatures, authRecs, true, boost::none);
  records.clear();
  records.push_back(dr2);
  MRC.replace(now, power2, QType(dr2.d_type), records, signatures, authRecs, true, boost::none);
  records.clear();
  BOOST_CHECK_EQUAL(MRC.size(), 2);

  /* the one for power2 having been inserted
     more recently should be removed last */
  /* we ask that only entry remains in the cache */
  MRC.doPrune(1);
  BOOST_CHECK_EQUAL(MRC.size(), 1);

  /* the remaining entry should be power2 */
  BOOST_CHECK_EQUAL(MRC.get(now, power2, QType(dr2.d_type), false, &retrieved, who, nullptr), ttd-now);
  BOOST_REQUIRE_EQUAL(retrieved.size(), 1);
  BOOST_CHECK_EQUAL(getRR<AAAARecordContent>(retrieved.at(0))->getCA().toString(), dr2Content.toString());
  /* check that power1 is gone */
  BOOST_CHECK_EQUAL(MRC.get(now, power1, QType(dr1.d_type), false, &retrieved, who, nullptr), -1);

  /* clear everything up */
  MRC.doWipeCache(DNSName("."), true);
  BOOST_CHECK_EQUAL(MRC.size(), 0);
  records.clear();

  /* insert both entries back */
  records.push_back(dr1);
  MRC.replace(now, power1, QType(dr1.d_type), records, signatures, authRecs, true, boost::none);
  records.clear();
  records.push_back(dr2);
  MRC.replace(now, power2, QType(dr2.d_type), records, signatures, authRecs, true, boost::none);
  records.clear();
  BOOST_CHECK_EQUAL(MRC.size(), 2);

  /* replace the entry for power1 */
  records.push_back(dr1);
  MRC.replace(now, power1, QType(dr1.d_type), records, signatures, authRecs, true, boost::none);
  records.clear();
  BOOST_CHECK_EQUAL(MRC.size(), 2);

  /* the replaced entry for power1 should have been moved
     to the back of the expunge queue, so power2 should be at the front
     and should this time be removed first */
  /* we ask that only entry remains in the cache */
  MRC.doPrune(1);
  BOOST_CHECK_EQUAL(MRC.size(), 1);

  /* the remaining entry should be power1 */
  BOOST_CHECK_EQUAL(MRC.get(now, power1, QType(dr1.d_type), false, &retrieved, who, nullptr), ttd-now);
  BOOST_REQUIRE_EQUAL(retrieved.size(), 1);
  BOOST_CHECK_EQUAL(getRR<AAAARecordContent>(retrieved.at(0))->getCA().toString(), dr1Content.toString());
  /* check that power2 is gone */
  BOOST_CHECK_EQUAL(MRC.get(now, power2, QType(dr2.d_type), false, &retrieved, who, nullptr), -1);

  /* clear everything up */
  MRC.doWipeCache(DNSName("."), true);
  BOOST_CHECK_EQUAL(MRC.size(), 0);
  records.clear();

  /* insert both entries back */
  records.push_back(dr1);
  MRC.replace(now, power1, QType(dr1.d_type), records, signatures, authRecs, true, boost::none);
  records.clear();
  records.push_back(dr2);
  MRC.replace(now, power2, QType(dr2.d_type), records, signatures, authRecs, true, boost::none);
  records.clear();
  BOOST_CHECK_EQUAL(MRC.size(), 2);

  /* get a hit for power1 */
  BOOST_CHECK_EQUAL(MRC.get(now, power1, QType(dr1.d_type), false, &retrieved, who, nullptr), ttd-now);
  BOOST_REQUIRE_EQUAL(retrieved.size(), 1);
  BOOST_CHECK_EQUAL(getRR<AAAARecordContent>(retrieved.at(0))->getCA().toString(), dr1Content.toString());

  /* the entry for power1 should have been moved to the back of the expunge queue
     due to the hit, so power2 should be at the front and should this time be removed first */
  /* we ask that only entry remains in the cache */
  MRC.doPrune(1);
  BOOST_CHECK_EQUAL(MRC.size(), 1);

  /* the remaining entry should be power1 */
  BOOST_CHECK_EQUAL(MRC.get(now, power1, QType(dr1.d_type), false, &retrieved, who, nullptr), ttd-now);
  BOOST_REQUIRE_EQUAL(retrieved.size(), 1);
  BOOST_CHECK_EQUAL(getRR<AAAARecordContent>(retrieved.at(0))->getCA().toString(), dr1Content.toString());
  /* check that power2 is gone */
  BOOST_CHECK_EQUAL(MRC.get(now, power2, QType(dr2.d_type), false, &retrieved, who, nullptr), -1);
}

BOOST_AUTO_TEST_SUITE_END()
