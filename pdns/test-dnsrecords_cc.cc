#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN
#include <boost/test/unit_test.hpp>
#include <boost/assign/list_of.hpp>
#include <boost/foreach.hpp>
#include <boost/tuple/tuple.hpp>
#include "dnsrecords.hh"

using namespace boost;
using namespace std;

#define LF(x) x, sizeof(x)-1

BOOST_AUTO_TEST_SUITE(dnsrecords_cc)

BOOST_AUTO_TEST_CASE(test_record_types) {
  typedef boost::tuple<const QType::typeenum, const std::string, const char*, size_t> case_t;
  typedef std::list<case_t> cases_t;
  reportAllTypes();

   cases_t cases = boost::assign::list_of
     (case_t(QType::A, "127.0.0.1", LF("\x7F\x00\x00\x01")))
// local nameserver
     (case_t(QType::NS, "ns.rec.test.", LF("\x02ns\xc0\x11")))
// non-local nameserver
     (case_t(QType::NS, "ns.example.com.", LF("\x02ns\x07""example\x03""com\x00")))
// local alias
     (case_t(QType::CNAME, "name.rec.test.", LF("\x04name\xc0\x11")))
// non-local alias
     (case_t(QType::CNAME, "name.example.com.", LF("\x04name\x07""example\x03""com\x00")))
// local names
     (case_t(QType::SOA, "ns.rec.test. hostmaster.test.rec. 2013051201 3600 3600 604800 120", LF("\x02ns\xc0\x11\x0ahostmaster\x04test\x03rec\x00\x77\xfc\xb9\x41\x00\x00\x0e\x10\x00\x00\x0e\x10\x00\x09\x3a\x80\x00\x00\x00\x78")))
// non-local names
     (case_t(QType::SOA, "ns.example.com. hostmaster.example.com. 2013051201 3600 3600 604800 120", LF("\x02ns\x07""example\x03""com\x00\x0ahostmaster\x07""example\x03""com\x00\x77\xfc\xb9\x41\x00\x00\x0e\x10\x00\x00\x0e\x10\x00\x09\x3a\x80\x00\x00\x00\x78")))

//     (case_t(QType::MR, "zone format", LF("line format")))
//     (case_t(QType::PTR, "zone format", LF("line format")))
//     (case_t(QType::HINFO, "zone format", LF("line format")))
//     (case_t(QType::MX, "zone format", LF("line format")))
//     (case_t(QType::TXT, "zone format", LF("line format")))
//     (case_t(QType::RP, "zone format", LF("line format")))
//     (case_t(QType::AFSDB, "zone format", LF("line format")))
//     (case_t(QType::KEY, "zone format", LF("line format")))
//     (case_t(QType::LOC, "zone format", LF("line format")))
     (case_t(QType::AAAA, "fe80::250:56ff:fe9b:114", LF("\xFE\x80\x00\x00\x00\x00\x00\x00\x02\x50\x56\xFF\xFE\x9B\x01\x14")))
//     (case_t(QType::SRV, "zone format", LF("line format")))
//     (case_t(QType::NAPTR, "zone format", LF("line format")))
//     (case_t(QType::KX, "zone format", LF("line format")))
//     (case_t(QType::CERT, "zone format", LF("line format")))
//     (case_t(QType::OPT, "zone format", LF("line format")))
//     (case_t(QType::DS, "zone format", LF("line format")))
//     (case_t(QType::SSHFP, "zone format", LF("line format")))
//     (case_t(QType::IPSECKEY, "zone format", LF("line format")))
//     (case_t(QType::RRSIG, "zone format", LF("line format")))
//     (case_t(QType::NSEC, "zone format", LF("line format")))
//     (case_t(QType::DNSKEY, "zone format", LF("line format")))
//     (case_t(QType::DHCID, "zone format", LF("line format")))
//     (case_t(QType::NSEC3, "zone format", LF("line format")))
//     (case_t(QType::NSEC3PARAM, "zone format", LF("line format")))
//     (case_t(QType::TLSA, "zone format", LF("line format")))
//     (case_t(QType::SPF, "zone format", LF("line format")))
     (case_t(QType::EUI48, "00-11-22-33-44-55", LF("\x00\x11\x22\x33\x44\x55")))
     (case_t(QType::EUI64, "00-11-22-33-44-55-66-77", LF("\x00\x11\x22\x33\x44\x55\x66\x77")));
//     (case_t(QType::TSIG, "zone format", LF("line format")))
//     (case_t(QType::AXFR, "zone format", LF("line format")))
//     (case_t(QType::IXFR, "zone format", LF("line format")))
//     (case_t(QType::ANY, "zone format", LF("line format")))
//     (case_t(QType::URL, "zone format", LF("line format")))
//     (case_t(QType::MBOXFW, "zone format", LF("line format")))
//     (case_t(QType::CURL, "zone format", LF("line format")))
//     (case_t(QType::ADDR, "zone format", LF("line format")))
//     (case_t(QType::DLV, "zone format", LF("line format")))

  BOOST_FOREACH(const cases_t::value_type& val, cases) {
   QType q(val.get<0>());
   DNSRecordContent *rec = DNSRecordContent::mastermake(q.getCode(), 1, val.get<1>());
   BOOST_CHECK(rec);
   // now verify the record
   BOOST_CHECK_EQUAL(rec->getZoneRepresentation(), val.get<1>());
   std::string recData = rec->serialize("rec.test");
   shared_ptr<DNSRecordContent> rec2 = DNSRecordContent::unserialize("rec.test",q.getCode(),recData);
   BOOST_CHECK_EQUAL(rec2->getZoneRepresentation(), val.get<1>());
   // and last, check the wire format (use hex format for error readability)
   string cmpData = makeHexDump(std::string(val.get<2>(), val.get<2>() + val.get<3>()));
   recData = makeHexDump(recData);
   BOOST_CHECK_EQUAL(recData, cmpData);
 }
}

BOOST_AUTO_TEST_SUITE_END()
