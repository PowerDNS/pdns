#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN
#include <boost/test/unit_test.hpp>
#include <boost/assign/list_of.hpp>
#include <boost/foreach.hpp>
#include <boost/tuple/tuple.hpp>
#include "dnsrecords.hh"

using namespace boost;
using namespace std;

BOOST_AUTO_TEST_SUITE(dnsrecords_cc)

BOOST_AUTO_TEST_CASE(test_record_types) {
  typedef boost::tuple<const QType::typeenum, const std::string, const char*, size_t> case_t;
  typedef std::list<case_t> cases_t;
  reportAllTypes();

   cases_t cases = boost::assign::list_of
     (case_t(QType::A, "127.0.0.1", "\x7F\x00\x00\x01",4))
     (case_t(QType::AAAA, "fe80::250:56ff:fe9b:114","\xFE\x80\x00\x00\x00\x00\x00\x00\x02\x50\x56\xFF\xFE\x9B\x01\x14",16))
     (case_t(QType::EUI48, "00-11-22-33-44-55","\x00\x11\x22\x33\x44\x55",6))
     (case_t(QType::EUI64, "00-11-22-33-44-55-66-77","\x00\x11\x22\x33\x44\x55\x66\x77",8));

  BOOST_FOREACH(const cases_t::value_type& val, cases) {
   QType q(val.get<0>());
   DNSRecordContent *rec = DNSRecordContent::mastermake(q.getCode(), 1, val.get<1>());
   BOOST_CHECK(rec);
   // now verify the record
   BOOST_CHECK_EQUAL(rec->getZoneRepresentation(), val.get<1>());
   std::string recData = rec->serialize("rec.test");
   shared_ptr<DNSRecordContent> rec2 = DNSRecordContent::unserialize("rec.test",q.getCode(),recData);
   BOOST_CHECK_EQUAL(rec2->getZoneRepresentation(), val.get<1>());
   // and last, check the wire format
   BOOST_CHECK_EQUAL(recData, std::string(val.get<2>(), val.get<2>() + val.get<3>()));
 }
}

BOOST_AUTO_TEST_SUITE_END()
