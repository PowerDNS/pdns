#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN

#include <boost/test/unit_test.hpp>
#include <boost/assign/list_of.hpp>
#include <boost/foreach.hpp>
#include <boost/tuple/tuple.hpp>
#include "pdns/namespaces.hh"
#include <pdns/dns.hh>
#include <pdns/dnsbackend.hh>
#include <pdns/dnspacket.hh>
#include <pdns/ueberbackend.hh>
#include <pdns/ahuexception.hh>
#include <pdns/logger.hh>
#include <pdns/arguments.hh>
#include <boost/lexical_cast.hpp>
#include <rapidjson/rapidjson.h>
#include <rapidjson/document.h>
#include "pdns/json.hh"
#include "pdns/statbag.hh"
#include "pdns/packetcache.hh"

#include "test-remotebackend-keys.hh"

extern DNSBackend *be;

BOOST_AUTO_TEST_SUITE(test_remotebackend_so)

BOOST_AUTO_TEST_CASE(test_method_lookup) {
   BOOST_TEST_MESSAGE("Testing lookup method");
   DNSResourceRecord rr;
   be->lookup(QType(QType::SOA), "unit.test");
   // then try to get()
   BOOST_CHECK(be->get(rr)); // and this should be TRUE.
   // then we check rr contains what we expect
   BOOST_CHECK_EQUAL(rr.qname, "unit.test");
   BOOST_CHECK_MESSAGE(rr.qtype == QType::SOA, "returned qtype was not SOA");
   BOOST_CHECK_EQUAL(rr.content, "ns.unit.test hostmaster.unit.test 1 2 3 4 5 6");
   BOOST_CHECK_EQUAL(rr.ttl, 300);
}

BOOST_AUTO_TEST_CASE(test_method_list) {
   int record_count = 0;
   DNSResourceRecord rr;

   BOOST_TEST_MESSAGE("Testing list method");
   be->list("unit.test", -1);
   while(be->get(rr)) record_count++;

   BOOST_CHECK_EQUAL(record_count, 5); // number of records our test domain has
}

BOOST_AUTO_TEST_CASE(test_method_doesDNSSEC) {
   BOOST_TEST_MESSAGE("Testing doesDNSSEC method");
   BOOST_CHECK(be->doesDNSSEC()); // should be true
}

BOOST_AUTO_TEST_CASE(test_method_setDomainMetadata) {
   std::vector<std::string> meta;
   meta.push_back("VALUE");
   BOOST_TEST_MESSAGE("Testing setDomainMetadata method");
   BOOST_CHECK(be->setDomainMetadata("unit.test","TEST", meta));
}

BOOST_AUTO_TEST_CASE(test_method_getDomainMetadata) {
   std::vector<std::string> meta;
   BOOST_TEST_MESSAGE("Testing getDomainMetadata method");
   be->getDomainMetadata("unit.test","TEST", meta);
   BOOST_CHECK_EQUAL(meta.size(), 1);
   // in case we got more than one value, which would be unexpected
   // but not fatal
   if (meta.size() > 0)
      BOOST_CHECK_EQUAL(meta[0], "VALUE");
}

BOOST_AUTO_TEST_CASE(test_method_addDomainKey) {
   BOOST_TEST_MESSAGE("Testing addDomainKey method");
   BOOST_CHECK_EQUAL(be->addDomainKey("unit.test",k1), 1);
   BOOST_CHECK_EQUAL(be->addDomainKey("unit.test",k2), 2);    
}

BOOST_AUTO_TEST_CASE(test_method_getDomainKeys) {
   std::vector<DNSBackend::KeyData> keys;
   BOOST_TEST_MESSAGE("Testing getDomainKeys method");
   // we expect to get two keys
   be->getDomainKeys("unit.test",0,keys);
   BOOST_CHECK_EQUAL(keys.size(), 2);
   // in case we got more than 2 keys, which would be unexpected
   // but not fatal
   if (keys.size() > 1) {
      // check that we have two keys
      BOOST_FOREACH(DNSBackend::KeyData &kd, keys) {
        BOOST_CHECK(kd.id > 0);
        BOOST_CHECK(kd.flags == 256 || kd.flags == 257);
        BOOST_CHECK(kd.active == true);
        BOOST_CHECK(kd.content.size() > 500);
      }
   }
}

BOOST_AUTO_TEST_CASE(test_method_deactivateDomainKey) {
   BOOST_TEST_MESSAGE("Testing deactivateDomainKey method");
   BOOST_CHECK(be->deactivateDomainKey("unit.test",1));
}

BOOST_AUTO_TEST_CASE(test_method_activateDomainKey) {
   BOOST_TEST_MESSAGE("Testing activateDomainKey method");
   BOOST_CHECK(be->activateDomainKey("unit.test",1));
}

BOOST_AUTO_TEST_CASE(test_method_removeDomainKey) {
   BOOST_CHECK(be->removeDomainKey("unit.test",2));
   BOOST_CHECK(be->removeDomainKey("unit.test",1));
}

BOOST_AUTO_TEST_CASE(test_method_getBeforeAndAfterNamesAbsolute) {
   std::string unhashed,before,after;
   BOOST_TEST_MESSAGE("Testing getBeforeAndAfterNamesAbsolute method");
   
   be->getBeforeAndAfterNamesAbsolute(-1, "middle.unit.test", unhashed, before, after);
   BOOST_CHECK_EQUAL(unhashed, "middle");
   BOOST_CHECK_EQUAL(before, "begin");
   BOOST_CHECK_EQUAL(after, "stop");
}

BOOST_AUTO_TEST_CASE(test_method_getTSIGKey) {
   std::string algorithm, content;
   BOOST_TEST_MESSAGE("Testing getTSIGKey method");
   be->getTSIGKey("unit.test",&algorithm,&content);
   BOOST_CHECK_EQUAL(algorithm, "NULL");
   BOOST_CHECK_EQUAL(content, "NULL");
}

BOOST_AUTO_TEST_CASE(test_method_setNotified) {
   BOOST_TEST_MESSAGE("Testing setNotified method");
   be->setNotified(1, 2);
   BOOST_CHECK(true); // we check this on next step
}

BOOST_AUTO_TEST_CASE(test_method_getDomainInfo) {
   DomainInfo di;
   BOOST_TEST_MESSAGE("Testing getDomainInfo method");
   be->getDomainInfo("unit.test", di);
   BOOST_CHECK_EQUAL(di.zone, "unit.test");
   BOOST_CHECK_EQUAL(di.serial, 2);
   BOOST_CHECK_EQUAL(di.notified_serial, 2);
   BOOST_CHECK_EQUAL(di.kind, DomainInfo::Native);
   BOOST_CHECK_EQUAL(di.backend, be);
}

BOOST_AUTO_TEST_CASE(test_method_superMasterBackend) {
   DNSResourceRecord rr;
   std::vector<DNSResourceRecord> nsset; 
   DNSBackend *dbd;
   BOOST_TEST_MESSAGE("Testing superMasterBackend method");

   rr.qname = "example.com";
   rr.qtype = QType::NS;
   rr.qclass = QClass::IN;
   rr.ttl = 300;
   rr.content = "ns1.example.com";
   nsset.push_back(rr);
   rr.qname = "example.com";
   rr.qtype = QType::NS;
   rr.qclass = QClass::IN;
   rr.ttl = 300;
   rr.content = "ns2.example.com";
   nsset.push_back(rr);

   BOOST_CHECK(be->superMasterBackend("10.0.0.1", "example.com", nsset, NULL, &dbd));

   // let's see what we got
   BOOST_CHECK_EQUAL(dbd, be);
}

BOOST_AUTO_TEST_CASE(test_method_createSlaveDomain) {
   BOOST_TEST_MESSAGE("Testing createSlaveDomain method");
   BOOST_CHECK(be->createSlaveDomain("10.0.0.1", "pirate.unit.test", ""));
}

BOOST_AUTO_TEST_CASE(test_method_feedRecord) {
   DNSResourceRecord rr;
   BOOST_TEST_MESSAGE("Testing feedRecord method");
   be->startTransaction("example.com",2);
   rr.qname = "example.com";
   rr.qtype = QType::SOA;
   rr.qclass = QClass::IN;
   rr.ttl = 300;
   rr.content = "ns1.example.com hostmaster.example.com 2013013441 7200 3600 1209600 300";
   BOOST_CHECK(be->feedRecord(rr, NULL));
   rr.qname = "replace.example.com";
   rr.qtype = QType::A;
   rr.qclass = QClass::IN;
   rr.ttl = 300;
   rr.content = "127.0.0.1";
   BOOST_CHECK(be->feedRecord(rr, NULL));
   be->commitTransaction();
}

BOOST_AUTO_TEST_CASE(test_method_replaceRRSet) {
   be->startTransaction("example.com",2);
   DNSResourceRecord rr;
   std::vector<DNSResourceRecord> rrset;
   BOOST_TEST_MESSAGE("Testing replaceRRSet method");
   rr.qname = "replace.example.com";
   rr.qtype = QType::A;
   rr.qclass = QClass::IN;
   rr.ttl = 300;
   rr.content = "1.1.1.1";
   rrset.push_back(rr);
   BOOST_CHECK(be->replaceRRSet(2, "replace.example.com", QType(QType::A), rrset));
   be->commitTransaction();
}

BOOST_AUTO_TEST_CASE(test_method_feedEnts) {
   BOOST_TEST_MESSAGE("Testing feedEnts method");
   be->startTransaction("example.com",2);
   set<string> nonterm = boost::assign::list_of("_udp")("_sip._udp");
   BOOST_CHECK(be->feedEnts(2, nonterm));
   be->commitTransaction();
}

BOOST_AUTO_TEST_CASE(test_method_feedEnts3) {
   BOOST_TEST_MESSAGE("Testing feedEnts3 method");
   be->startTransaction("example.com",2);
   set<string> nonterm = boost::assign::list_of("_udp")("_sip._udp");
   BOOST_CHECK(be->feedEnts3(2, "example.com", nonterm, 1, "\xaa\xbb\xcc\xdd", 0));
   be->commitTransaction();
}

BOOST_AUTO_TEST_CASE(test_method_abortTransaction) {
   BOOST_TEST_MESSAGE("Testing abortTransaction method");
   be->startTransaction("example.com",2);
   BOOST_CHECK(be->abortTransaction());
}

BOOST_AUTO_TEST_CASE(test_method_calculateSOASerial) {
   SOAData sd;
   time_t serial;
 
   be->getSOA("unit.test",sd);
   BOOST_CHECK(be->calculateSOASerial("unit.test",sd,serial));

   BOOST_CHECK_EQUAL(serial, 2013060300);
}

BOOST_AUTO_TEST_SUITE_END();
