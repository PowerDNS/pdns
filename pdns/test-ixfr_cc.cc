#ifndef BOOST_TEST_DYN_LINK
#define BOOST_TEST_DYN_LINK
#endif

#define BOOST_TEST_NO_MAIN

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <boost/test/unit_test.hpp>

#include "test-common.hh"
#include "ixfr.hh"

BOOST_AUTO_TEST_SUITE(test_ixfr_cc)

BOOST_AUTO_TEST_CASE(test_ixfr_rfc1995_axfr) {
  const ComboAddress primary("[2001:DB8::1]:53");
  const DNSName zone("JAIN.AD.JP.");

  auto primarySOA = DNSRecordContent::make(QType::SOA, QClass::IN, "NS.JAIN.AD.JP. mohta.jain.ad.jp. 3 600 600 3600000 604800");
  vector<DNSRecord> records;
  addRecordToList(records, DNSName("JAIN.AD.JP."), QType::SOA, "ns.jain.ad.jp. mohta.jain.ad.jp. 3 600 600 3600000 604800");
  addRecordToList(records, DNSName("JAIN.AD.JP."), QType::NS, "NS.JAIN.AD.JP.");
  addRecordToList(records, DNSName("NS.JAIN.AD.JP."), QType::A, "133.69.136.1");
  addRecordToList(records, DNSName("JAIN-BB.JAIN.AD.JP."), QType::A, "133.69.136.3");
  addRecordToList(records, DNSName("JAIN-BB.JAIN.AD.JP."), QType::A, "192.41.197.2");
  addRecordToList(records, DNSName("JAIN.AD.JP."), QType::SOA, "ns.jain.ad.jp. mohta.jain.ad.jp. 3 600 600 3600000 604800");

  auto ret = processIXFRRecords(primary, zone, records, std::dynamic_pointer_cast<SOARecordContent>(primarySOA));
  BOOST_CHECK_EQUAL(ret.size(), 1U);
  BOOST_CHECK_EQUAL(ret.at(0).first.size(), 0U);
  BOOST_REQUIRE_EQUAL(ret.at(0).second.size(), records.size());
  for (size_t idx = 0; idx < records.size(); idx++) {
    BOOST_CHECK(ret.at(0).second.at(idx) == records.at(idx));
  }
}

BOOST_AUTO_TEST_CASE(test_ixfr_rfc1995_incremental) {
  const ComboAddress primary("[2001:DB8::1]:53");
  const DNSName zone("JAIN.AD.JP.");

  auto primarySOA = DNSRecordContent::make(QType::SOA, QClass::IN, "NS.JAIN.AD.JP. mohta.jain.ad.jp. 3 600 600 3600000 604800");
  vector<DNSRecord> records;
  addRecordToList(records, DNSName("JAIN.AD.JP."), QType::SOA, "ns.jain.ad.jp. mohta.jain.ad.jp. 3 600 600 3600000 604800");
  addRecordToList(records, DNSName("JAIN.AD.JP."), QType::SOA, "ns.jain.ad.jp. mohta.jain.ad.jp. 1 600 600 3600000 604800");
  addRecordToList(records, DNSName("NEZU.JAIN.AD.JP."), QType::A, "133.69.136.5");
  addRecordToList(records, DNSName("JAIN.AD.JP."), QType::SOA, "ns.jain.ad.jp. mohta.jain.ad.jp. 2 600 600 3600000 604800");
  addRecordToList(records, DNSName("JAIN-BB.JAIN.AD.JP."), QType::A, "133.69.136.4");
  addRecordToList(records, DNSName("JAIN-BB.JAIN.AD.JP."), QType::A, "192.41.197.2");
  addRecordToList(records, DNSName("JAIN.AD.JP."), QType::SOA, "ns.jain.ad.jp. mohta.jain.ad.jp. 2 600 600 3600000 604800");
  addRecordToList(records, DNSName("JAIN-BB.JAIN.AD.JP."), QType::A, "133.69.136.4");
  addRecordToList(records, DNSName("JAIN.AD.JP."), QType::SOA, "ns.jain.ad.jp. mohta.jain.ad.jp. 3 600 600 3600000 604800");
  addRecordToList(records, DNSName("JAIN-BB.JAIN.AD.JP."), QType::A, "133.69.136.3");
  addRecordToList(records, DNSName("JAIN.AD.JP."), QType::SOA, "ns.jain.ad.jp. mohta.jain.ad.jp. 3 600 600 3600000 604800");

  auto ret = processIXFRRecords(primary, zone, records, std::dynamic_pointer_cast<SOARecordContent>(primarySOA));
  // two sequences
  BOOST_CHECK_EQUAL(ret.size(), 2U);
  // the first one has one removal, two additions (plus the corresponding SOA removal/addition)
  BOOST_CHECK_EQUAL(ret.at(0).first.size(), 1U + 1U);
  BOOST_CHECK_EQUAL(ret.at(0).second.size(), 2U + 1U);

  // check removals
  BOOST_CHECK_EQUAL(ret.at(0).first.at(0).d_type, QType(QType::SOA).getCode());
  BOOST_CHECK_EQUAL(ret.at(0).first.at(1).d_type, QType(QType::A).getCode());

  // check additions
  BOOST_CHECK_EQUAL(ret.at(0).second.at(0).d_type, QType(QType::SOA).getCode());
  BOOST_CHECK_EQUAL(ret.at(0).second.at(1).d_type, QType(QType::A).getCode());
  BOOST_CHECK_EQUAL(ret.at(0).second.at(2).d_type, QType(QType::A).getCode());

  // the second one has one removal, one addition
  BOOST_CHECK_EQUAL(ret.at(1).first.size(), 1U + 1U);
  BOOST_CHECK_EQUAL(ret.at(1).second.size(), 1U + 1U);

  // check removals
  BOOST_CHECK_EQUAL(ret.at(1).first.at(0).d_type, QType(QType::SOA).getCode());
  BOOST_CHECK_EQUAL(ret.at(1).first.at(1).d_type, QType(QType::A).getCode());

  // check additions
  BOOST_CHECK_EQUAL(ret.at(1).second.at(0).d_type, QType(QType::SOA).getCode());
  BOOST_CHECK_EQUAL(ret.at(1).second.at(1).d_type, QType(QType::A).getCode());
}

BOOST_AUTO_TEST_CASE(test_ixfr_rfc1995_condensed_incremental) {
  const ComboAddress primary("[2001:DB8::1]:53");
  const DNSName zone("JAIN.AD.JP.");

  auto primarySOA = DNSRecordContent::make(QType::SOA, QClass::IN, "NS.JAIN.AD.JP. mohta.jain.ad.jp. 3 600 600 3600000 604800");
  vector<DNSRecord> records;
  addRecordToList(records, DNSName("JAIN.AD.JP."), QType::SOA, "ns.jain.ad.jp. mohta.jain.ad.jp. 3 600 600 3600000 604800");
  addRecordToList(records, DNSName("JAIN.AD.JP."), QType::SOA, "ns.jain.ad.jp. mohta.jain.ad.jp. 1 600 600 3600000 604800");
  addRecordToList(records, DNSName("NEZU.JAIN.AD.JP."), QType::A, "133.69.136.5");
  addRecordToList(records, DNSName("JAIN.AD.JP."), QType::SOA, "ns.jain.ad.jp. mohta.jain.ad.jp. 3 600 600 3600000 604800");
  addRecordToList(records, DNSName("JAIN-BB.JAIN.AD.JP."), QType::A, "133.69.136.3");
  addRecordToList(records, DNSName("JAIN-BB.JAIN.AD.JP."), QType::A, "192.41.197.2");
  addRecordToList(records, DNSName("JAIN.AD.JP."), QType::SOA, "ns.jain.ad.jp. mohta.jain.ad.jp. 3 600 600 3600000 604800");

  auto ret = processIXFRRecords(primary, zone, records, std::dynamic_pointer_cast<SOARecordContent>(primarySOA));
  // one sequence
  BOOST_CHECK_EQUAL(ret.size(), 1U);
  // it has one removal, two additions (plus the corresponding SOA removal/addition)
  BOOST_CHECK_EQUAL(ret.at(0).first.size(), 1U + 1U);
  BOOST_CHECK_EQUAL(ret.at(0).second.size(), 2U + 1U);

  // check removals
  BOOST_CHECK_EQUAL(ret.at(0).first.at(0).d_type, QType(QType::SOA).getCode());
  BOOST_CHECK_EQUAL(ret.at(0).first.at(1).d_type, QType(QType::A).getCode());

  // check additions
  BOOST_CHECK_EQUAL(ret.at(0).second.at(0).d_type, QType(QType::SOA).getCode());
  BOOST_CHECK_EQUAL(ret.at(0).second.at(1).d_type, QType(QType::A).getCode());
  BOOST_CHECK_EQUAL(ret.at(0).second.at(2).d_type, QType(QType::A).getCode());
}

BOOST_AUTO_TEST_CASE(test_ixfr_no_additions_in_first_sequence) {
  const ComboAddress primary("[2001:DB8::1]:53");
  const DNSName zone("JAIN.AD.JP.");

  auto primarySOA = DNSRecordContent::make(QType::SOA, QClass::IN, "NS.JAIN.AD.JP. mohta.jain.ad.jp. 3 600 600 3600000 604800");
  vector<DNSRecord> records;
  addRecordToList(records, DNSName("JAIN.AD.JP."), QType::SOA, "ns.jain.ad.jp. mohta.jain.ad.jp. 3 600 600 3600000 604800");
  addRecordToList(records, DNSName("JAIN.AD.JP."), QType::SOA, "ns.jain.ad.jp. mohta.jain.ad.jp. 1 600 600 3600000 604800");
  addRecordToList(records, DNSName("NEZU.JAIN.AD.JP."), QType::A, "133.69.136.5");
  addRecordToList(records, DNSName("JAIN.AD.JP."), QType::SOA, "ns.jain.ad.jp. mohta.jain.ad.jp. 2 600 600 3600000 604800");
  addRecordToList(records, DNSName("JAIN.AD.JP."), QType::SOA, "ns.jain.ad.jp. mohta.jain.ad.jp. 2 600 600 3600000 604800");
  addRecordToList(records, DNSName("JAIN-BB.JAIN.AD.JP."), QType::A, "133.69.136.5");
  addRecordToList(records, DNSName("JAIN.AD.JP."), QType::SOA, "ns.jain.ad.jp. mohta.jain.ad.jp. 3 600 600 3600000 604800");
  addRecordToList(records, DNSName("JAIN-BB.JAIN.AD.JP."), QType::A, "133.69.136.3");
  addRecordToList(records, DNSName("JAIN.AD.JP."), QType::SOA, "ns.jain.ad.jp. mohta.jain.ad.jp. 3 600 600 3600000 604800");

  auto ret = processIXFRRecords(primary, zone, records, std::dynamic_pointer_cast<SOARecordContent>(primarySOA));
  // two sequences
  BOOST_CHECK_EQUAL(ret.size(), 2U);
  // the first one has one removal, no additions (plus the corresponding SOA removal/addition)
  BOOST_CHECK_EQUAL(ret.at(0).first.size(), 1U + 1U);
  BOOST_CHECK_EQUAL(ret.at(0).second.size(), 0U + 1U);

  // check removals
  BOOST_CHECK_EQUAL(ret.at(0).first.at(0).d_type, QType(QType::SOA).getCode());
  BOOST_CHECK_EQUAL(ret.at(0).first.at(1).d_type, QType(QType::A).getCode());

  // check additions
  BOOST_CHECK_EQUAL(ret.at(0).second.at(0).d_type, QType(QType::SOA).getCode());

  // the second one has one removal, one addition
  BOOST_CHECK_EQUAL(ret.at(1).first.size(), 1U + 1U);
  BOOST_CHECK_EQUAL(ret.at(1).second.size(), 1U + 1U);

  // check removals
  BOOST_CHECK_EQUAL(ret.at(1).first.at(0).d_type, QType(QType::SOA).getCode());
  BOOST_CHECK_EQUAL(ret.at(1).first.at(1).d_type, QType(QType::A).getCode());

  // check additions
  BOOST_CHECK_EQUAL(ret.at(1).second.at(0).d_type, QType(QType::SOA).getCode());
  BOOST_CHECK_EQUAL(ret.at(1).second.at(1).d_type, QType(QType::A).getCode());
}

BOOST_AUTO_TEST_CASE(test_ixfr_no_removals_in_first_sequence) {
  const ComboAddress primary("[2001:DB8::1]:53");
  const DNSName zone("JAIN.AD.JP.");

  auto primarySOA = DNSRecordContent::make(QType::SOA, QClass::IN, "NS.JAIN.AD.JP. mohta.jain.ad.jp. 3 600 600 3600000 604800");
  vector<DNSRecord> records;
  addRecordToList(records, DNSName("JAIN.AD.JP."), QType::SOA, "ns.jain.ad.jp. mohta.jain.ad.jp. 3 600 600 3600000 604800");
  addRecordToList(records, DNSName("JAIN.AD.JP."), QType::SOA, "ns.jain.ad.jp. mohta.jain.ad.jp. 1 600 600 3600000 604800");
  addRecordToList(records, DNSName("JAIN.AD.JP."), QType::SOA, "ns.jain.ad.jp. mohta.jain.ad.jp. 2 600 600 3600000 604800");
  addRecordToList(records, DNSName("JAIN-BB.JAIN.AD.JP."), QType::A, "133.69.136.4");
  addRecordToList(records, DNSName("JAIN-BB.JAIN.AD.JP."), QType::A, "192.41.197.2");
  addRecordToList(records, DNSName("JAIN.AD.JP."), QType::SOA, "ns.jain.ad.jp. mohta.jain.ad.jp. 2 600 600 3600000 604800");
  addRecordToList(records, DNSName("JAIN-BB.JAIN.AD.JP."), QType::A, "133.69.136.4");
  addRecordToList(records, DNSName("JAIN.AD.JP."), QType::SOA, "ns.jain.ad.jp. mohta.jain.ad.jp. 3 600 600 3600000 604800");
  addRecordToList(records, DNSName("JAIN-BB.JAIN.AD.JP."), QType::A, "133.69.136.3");
  addRecordToList(records, DNSName("JAIN.AD.JP."), QType::SOA, "ns.jain.ad.jp. mohta.jain.ad.jp. 3 600 600 3600000 604800");

  auto ret = processIXFRRecords(primary, zone, records, std::dynamic_pointer_cast<SOARecordContent>(primarySOA));
  // two sequences
  BOOST_CHECK_EQUAL(ret.size(), 2U);
  // the first one has no removal, two additions (plus the corresponding SOA removal/addition)
  BOOST_CHECK_EQUAL(ret.at(0).first.size(), 0U + 1U);
  BOOST_CHECK_EQUAL(ret.at(0).second.size(), 2U + 1U);

  // check removals
  BOOST_CHECK_EQUAL(ret.at(0).first.at(0).d_type, QType(QType::SOA).getCode());

  // check additions
  BOOST_CHECK_EQUAL(ret.at(0).second.at(0).d_type, QType(QType::SOA).getCode());
  BOOST_CHECK_EQUAL(ret.at(0).second.at(1).d_type, QType(QType::A).getCode());
  BOOST_CHECK_EQUAL(ret.at(0).second.at(1).d_type, QType(QType::A).getCode());

  // the second one has one removal, one addition
  BOOST_CHECK_EQUAL(ret.at(1).first.size(), 1U + 1U);
  BOOST_CHECK_EQUAL(ret.at(1).second.size(), 1U + 1U);

  // check removals
  BOOST_CHECK_EQUAL(ret.at(1).first.at(0).d_type, QType(QType::SOA).getCode());
  BOOST_CHECK_EQUAL(ret.at(1).first.at(1).d_type, QType(QType::A).getCode());

  // check additions
  BOOST_CHECK_EQUAL(ret.at(1).second.at(0).d_type, QType(QType::SOA).getCode());
  BOOST_CHECK_EQUAL(ret.at(1).second.at(1).d_type, QType(QType::A).getCode());
}

BOOST_AUTO_TEST_CASE(test_ixfr_same_serial) {
  const ComboAddress primary("[2001:DB8::1]:53");
  const DNSName zone("JAIN.AD.JP.");

  auto primarySOA = DNSRecordContent::make(QType::SOA, QClass::IN, "NS.JAIN.AD.JP. mohta.jain.ad.jp. 3 600 600 3600000 604800");
  vector<DNSRecord> records;
  addRecordToList(records, DNSName("JAIN.AD.JP."), QType::SOA, "ns.jain.ad.jp. mohta.jain.ad.jp. 3 600 600 3600000 604800");
  addRecordToList(records, DNSName("JAIN.AD.JP."), QType::SOA, "ns.jain.ad.jp. mohta.jain.ad.jp. 3 600 600 3600000 604800");

  auto ret = processIXFRRecords(primary, zone, records, std::dynamic_pointer_cast<SOARecordContent>(primarySOA));

  // this is actually an empty AXFR
  BOOST_CHECK_EQUAL(ret.size(), 1U);
  // nothing in the deletion part then
  BOOST_CHECK_EQUAL(ret.at(0).first.size(), 0U);
  // and the two SOAs in the addition part
  BOOST_CHECK_EQUAL(ret.at(0).second.size(), 2U);
  BOOST_CHECK_EQUAL(ret.at(0).second.at(0).d_type, QType(QType::SOA).getCode());
  BOOST_CHECK_EQUAL(ret.at(0).second.at(1).d_type, QType(QType::SOA).getCode());
}

BOOST_AUTO_TEST_CASE(test_ixfr_invalid_no_records) {
  const ComboAddress primary("[2001:DB8::1]:53");
  const DNSName zone("JAIN.AD.JP.");

  auto primarySOA = DNSRecordContent::make(QType::SOA, QClass::IN, "NS.JAIN.AD.JP. mohta.jain.ad.jp. 3 600 600 3600000 604800");
  vector<DNSRecord> records;

  auto ret = processIXFRRecords(primary, zone, records, std::dynamic_pointer_cast<SOARecordContent>(primarySOA));
  BOOST_CHECK_EQUAL(ret.size(), 0U);
}

BOOST_AUTO_TEST_CASE(test_ixfr_invalid_no_primary_soa)
{
  const ComboAddress primary("[2001:DB8::1]:53");
  const DNSName zone("JAIN.AD.JP.");
;
  vector<DNSRecord> records;
  addRecordToList(records, DNSName("JAIN.AD.JP."), QType::SOA, "ns.jain.ad.jp. mohta.jain.ad.jp. 3 600 600 3600000 604800");

  auto ret = processIXFRRecords(primary, zone, records, nullptr);
  BOOST_CHECK_EQUAL(ret.size(), 0U);
}

BOOST_AUTO_TEST_CASE(test_ixfr_invalid_no_trailing_soa) {
  const ComboAddress primary("[2001:DB8::1]:53");
  const DNSName zone("JAIN.AD.JP.");

  auto primarySOA = DNSRecordContent::make(QType::SOA, QClass::IN, "NS.JAIN.AD.JP. mohta.jain.ad.jp. 3 600 600 3600000 604800");
  vector<DNSRecord> records;
  addRecordToList(records, DNSName("JAIN.AD.JP."), QType::SOA, "ns.jain.ad.jp. mohta.jain.ad.jp. 3 600 600 3600000 604800");
  addRecordToList(records, DNSName("JAIN.AD.JP."), QType::SOA, "ns.jain.ad.jp. mohta.jain.ad.jp. 1 600 600 3600000 604800");
  addRecordToList(records, DNSName("NEZU.JAIN.AD.JP."), QType::A, "133.69.136.5");
  addRecordToList(records, DNSName("JAIN.AD.JP."), QType::SOA, "ns.jain.ad.jp. mohta.jain.ad.jp. 3 600 600 3600000 604800");
  addRecordToList(records, DNSName("JAIN-BB.JAIN.AD.JP."), QType::A, "133.69.136.3");
  addRecordToList(records, DNSName("JAIN-BB.JAIN.AD.JP."), QType::A, "192.41.197.2");

  BOOST_CHECK_THROW(processIXFRRecords(primary, zone, records, std::dynamic_pointer_cast<SOARecordContent>(primarySOA)), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(test_ixfr_invalid_no_soa_after_removals) {
  const ComboAddress primary("[2001:DB8::1]:53");
  const DNSName zone("JAIN.AD.JP.");

  auto primarySOA = DNSRecordContent::make(QType::SOA, QClass::IN, "NS.JAIN.AD.JP. mohta.jain.ad.jp. 3 600 600 3600000 604800");
  vector<DNSRecord> records;
  addRecordToList(records, DNSName("JAIN.AD.JP."), QType::SOA, "ns.jain.ad.jp. mohta.jain.ad.jp. 3 600 600 3600000 604800");
  addRecordToList(records, DNSName("JAIN.AD.JP."), QType::SOA, "ns.jain.ad.jp. mohta.jain.ad.jp. 1 600 600 3600000 604800");
  addRecordToList(records, DNSName("NEZU.JAIN.AD.JP."), QType::A, "133.69.136.5");

  BOOST_CHECK_THROW(processIXFRRecords(primary, zone, records, std::dynamic_pointer_cast<SOARecordContent>(primarySOA)), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(test_ixfr_mismatching_serial_before_and_after_additions) {
  const ComboAddress primary("[2001:DB8::1]:53");
  const DNSName zone("JAIN.AD.JP.");

  auto primarySOA = DNSRecordContent::make(QType::SOA, QClass::IN, "NS.JAIN.AD.JP. mohta.jain.ad.jp. 3 600 600 3600000 604800");
  vector<DNSRecord> records;
  addRecordToList(records, DNSName("JAIN.AD.JP."), QType::SOA, "ns.jain.ad.jp. mohta.jain.ad.jp. 3 600 600 3600000 604800");
  addRecordToList(records, DNSName("JAIN.AD.JP."), QType::SOA, "ns.jain.ad.jp. mohta.jain.ad.jp. 1 600 600 3600000 604800");
  addRecordToList(records, DNSName("NEZU.JAIN.AD.JP."), QType::A, "133.69.136.5");
  addRecordToList(records, DNSName("JAIN.AD.JP."), QType::SOA, "ns.jain.ad.jp. mohta.jain.ad.jp. 2 600 600 3600000 604800");
  addRecordToList(records, DNSName("JAIN-BB.JAIN.AD.JP."), QType::A, "133.69.136.3");
  addRecordToList(records, DNSName("JAIN-BB.JAIN.AD.JP."), QType::A, "192.41.197.2");
  addRecordToList(records, DNSName("JAIN.AD.JP."), QType::SOA, "ns.jain.ad.jp. mohta.jain.ad.jp. 3 600 600 3600000 604800");

  BOOST_CHECK_THROW(processIXFRRecords(primary, zone, records, std::dynamic_pointer_cast<SOARecordContent>(primarySOA)), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(test_ixfr_trailing_record_after_end) {
  const ComboAddress primary("[2001:DB8::1]:53");
  const DNSName zone("JAIN.AD.JP.");

  auto primarySOA = DNSRecordContent::make(QType::SOA, QClass::IN, "NS.JAIN.AD.JP. mohta.jain.ad.jp. 3 600 600 3600000 604800");
  vector<DNSRecord> records;
  addRecordToList(records, DNSName("JAIN.AD.JP."), QType::SOA, "ns.jain.ad.jp. mohta.jain.ad.jp. 3 600 600 3600000 604800");
  addRecordToList(records, DNSName("JAIN.AD.JP."), QType::SOA, "ns.jain.ad.jp. mohta.jain.ad.jp. 1 600 600 3600000 604800");
  addRecordToList(records, DNSName("NEZU.JAIN.AD.JP."), QType::A, "133.69.136.5");
  addRecordToList(records, DNSName("JAIN.AD.JP."), QType::SOA, "ns.jain.ad.jp. mohta.jain.ad.jp. 3 600 600 3600000 604800");
  addRecordToList(records, DNSName("JAIN-BB.JAIN.AD.JP."), QType::A, "133.69.136.3");
  addRecordToList(records, DNSName("JAIN-BB.JAIN.AD.JP."), QType::A, "192.41.197.2");
  addRecordToList(records, DNSName("JAIN.AD.JP."), QType::SOA, "ns.jain.ad.jp. mohta.jain.ad.jp. 3 600 600 3600000 604800");
  addRecordToList(records, DNSName("JAIN-BB.JAIN.AD.JP."), QType::A, "133.69.136.3");

  BOOST_CHECK_THROW(processIXFRRecords(primary, zone, records, std::dynamic_pointer_cast<SOARecordContent>(primarySOA)), std::runtime_error);
}

BOOST_AUTO_TEST_SUITE_END();
