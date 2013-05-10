#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN
#include <boost/test/unit_test.hpp>
#include <boost/assign/std/map.hpp>
#include <boost/foreach.hpp>
#include "dnsrecords.hh"

using namespace boost;
using namespace std;

BOOST_AUTO_TEST_SUITE(dnsrecords_cc)

BOOST_AUTO_TEST_CASE(test_EUI48) {
   EUI48RecordContent::report();
   std::string lineformat="\x00\x11\x22\x33\x44\x55";
   std::string zoneformat="00-11-22-33-44-55";

   DNSRecordContent *rec = DNSRecordContent::mastermake(QType::EUI48, 1, zoneformat);
   
   BOOST_CHECK(rec);

   // now verify the record
   BOOST_CHECK_EQUAL(rec->getZoneRepresentation(), zoneformat);
   shared_ptr<DNSRecordContent> rec2 = DNSRecordContent::unserialize("eui48.test",ns_t_eui48,rec->serialize("eui48.test"));
   
   BOOST_CHECK(rec2);
   BOOST_CHECK_EQUAL(rec2->getZoneRepresentation(), zoneformat);
}

BOOST_AUTO_TEST_CASE(test_EUI64) {
   EUI64RecordContent::report();
   std::string lineformat="\x00\x11\x22\x33\x44\x55\x66\x77";
   std::string zoneformat="00-11-22-33-44-55-66-77";

   DNSRecordContent *rec = DNSRecordContent::mastermake(QType::EUI64, 1, zoneformat);

   BOOST_CHECK(rec);

   // now verify the record
   BOOST_CHECK_EQUAL(rec->getZoneRepresentation(), zoneformat);
   shared_ptr<DNSRecordContent> rec2 = DNSRecordContent::unserialize("eui64.test",ns_t_eui64,rec->serialize("eui64.test"));

   BOOST_CHECK(rec2);
   BOOST_CHECK_EQUAL(rec2->getZoneRepresentation(), zoneformat);
}


BOOST_AUTO_TEST_SUITE_END()


