#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN
#include <boost/test/unit_test.hpp>
#include <boost/assign/std/map.hpp>
#include <boost/foreach.hpp>
#include "dnsrecords.hh"

using namespace boost;
using namespace std;

BOOST_AUTO_TEST_SUITE(dnsrecords_cc)

BOOST_AUTO_TEST_CASE(test_record_types) {
  typedef std::map<QType::typeenum, std::string> cases_t;
   reportAllTypes();

   cases_t cases;
   assign::insert(cases)
     (QType::A, "127.0.0.1")
     (QType::AAAA, "fe80::250:56ff:fe9b:114")
     (QType::EUI48, "00-11-22-33-44-55")
     (QType::EUI64, "00-11-22-33-44-55-66-77");

  BOOST_FOREACH(const cases_t::value_type& val, cases) {
   QType q(val.first);
   DNSRecordContent *rec = DNSRecordContent::mastermake(q.getCode(), 1, val.second);
   BOOST_CHECK(rec);
   // now verify the record
   BOOST_CHECK_EQUAL(rec->getZoneRepresentation(), val.second);
   shared_ptr<DNSRecordContent> rec2 = DNSRecordContent::unserialize("rec.test",q.getCode(),rec->serialize("rec.test"));
   BOOST_CHECK_EQUAL(rec2->getZoneRepresentation(), val.second);
 }
}

BOOST_AUTO_TEST_SUITE_END()


