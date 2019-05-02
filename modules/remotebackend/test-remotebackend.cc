/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * In addition, for the avoidance of any doubt, permission is granted to
 * link this program with OpenSSL and to (re)distribute the binaries
 * produced as the result of such linking.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <boost/test/unit_test.hpp>
#include <boost/assign/list_of.hpp>

#include <boost/tuple/tuple.hpp>
#include "pdns/namespaces.hh"
#include "pdns/dns.hh"
#include "pdns/dnsbackend.hh"
#include "pdns/dnspacket.hh"
#include "pdns/pdnsexception.hh"
#include "pdns/logger.hh"
#include "pdns/arguments.hh"
#include "pdns/json.hh"
#include "pdns/statbag.hh"

#include "test-remotebackend-keys.hh"

extern DNSBackend *be;

BOOST_AUTO_TEST_SUITE(test_remotebackend_so)

BOOST_AUTO_TEST_CASE(test_method_lookup) {
   BOOST_TEST_MESSAGE("Testing lookup method");
   DNSResourceRecord rr;
   be->lookup(QType(QType::SOA), DNSName("unit.test."));
   // then try to get()
   BOOST_CHECK(be->get(rr)); // and this should be TRUE.
   // then we check rr contains what we expect
   BOOST_CHECK_EQUAL(rr.qname.toString(), "unit.test.");
   BOOST_CHECK_MESSAGE(rr.qtype == QType::SOA, "returned qtype was not SOA");
   BOOST_CHECK_EQUAL(rr.content, "ns.unit.test. hostmaster.unit.test. 1 2 3 4 5");
   BOOST_CHECK_EQUAL(rr.ttl, 300);
}

BOOST_AUTO_TEST_CASE(test_method_lookup_empty) {
   BOOST_TEST_MESSAGE("Testing lookup method with empty result");
   DNSResourceRecord rr;
   be->lookup(QType(QType::SOA), DNSName("empty.unit.test."));
   // then try to get()
   BOOST_CHECK(!be->get(rr)); // and this should be FALSE
}

BOOST_AUTO_TEST_CASE(test_method_list) {
   int record_count = 0;
   DNSResourceRecord rr;

   BOOST_TEST_MESSAGE("Testing list method");
   be->list(DNSName("unit.test."), -1);
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
   BOOST_CHECK(be->setDomainMetadata(DNSName("unit.test."),"TEST", meta));
}

BOOST_AUTO_TEST_CASE(test_method_getDomainMetadata) {
   std::vector<std::string> meta;
   BOOST_TEST_MESSAGE("Testing getDomainMetadata method");
   be->getDomainMetadata(DNSName("unit.test."),"TEST", meta);
   BOOST_CHECK_EQUAL(meta.size(), 1);
   // in case we got more than one value, which would be unexpected
   // but not fatal
   if (meta.size() > 0)
      BOOST_CHECK_EQUAL(meta[0], "VALUE");
}

BOOST_AUTO_TEST_CASE(test_method_getAllDomainMetadata) {
   std::map<std::string, std::vector<std::string> > meta;
   BOOST_TEST_MESSAGE("Testing getAllDomainMetadata method");
   be->getAllDomainMetadata(DNSName("unit.test."), meta);
   BOOST_CHECK_EQUAL(meta.size(), 1);
   // in case we got more than one value, which would be unexpected
   // but not fatal
   if (meta.size() > 0)
      BOOST_CHECK_EQUAL(meta["TEST"][0], "VALUE");
}

BOOST_AUTO_TEST_CASE(test_method_addDomainKey) {
   BOOST_TEST_MESSAGE("Testing addDomainKey method");
   int64_t id;
   be->addDomainKey(DNSName("unit.test."),k1,id);
   BOOST_CHECK_EQUAL(id, 1);
   be->addDomainKey(DNSName("unit.test."),k2,id);
   BOOST_CHECK_EQUAL(id, 2);
}

BOOST_AUTO_TEST_CASE(test_method_getDomainKeys) {
   std::vector<DNSBackend::KeyData> keys;
   BOOST_TEST_MESSAGE("Testing getDomainKeys method");
   // we expect to get two keys
   be->getDomainKeys(DNSName("unit.test."),keys);
   BOOST_CHECK_EQUAL(keys.size(), 2);
   // in case we got more than 2 keys, which would be unexpected
   // but not fatal
   if (keys.size() > 1) {
      // check that we have two keys
      for(DNSBackend::KeyData &kd :  keys) {
        BOOST_CHECK(kd.id > 0);
        BOOST_CHECK(kd.flags == 256 || kd.flags == 257);
        BOOST_CHECK(kd.active == true);
        BOOST_CHECK(kd.content.size() > 500);
      }
   }
}

BOOST_AUTO_TEST_CASE(test_method_deactivateDomainKey) {
   BOOST_TEST_MESSAGE("Testing deactivateDomainKey method");
   BOOST_CHECK(be->deactivateDomainKey(DNSName("unit.test."),1));
}

BOOST_AUTO_TEST_CASE(test_method_activateDomainKey) {
   BOOST_TEST_MESSAGE("Testing activateDomainKey method");
   BOOST_CHECK(be->activateDomainKey(DNSName("unit.test."),1));
}

BOOST_AUTO_TEST_CASE(test_method_removeDomainKey) {
   BOOST_CHECK(be->removeDomainKey(DNSName("unit.test."),2));
   BOOST_CHECK(be->removeDomainKey(DNSName("unit.test."),1));
}

BOOST_AUTO_TEST_CASE(test_method_getBeforeAndAfterNamesAbsolute) {
   DNSName unhashed, before, after;
   BOOST_TEST_MESSAGE("Testing getBeforeAndAfterNamesAbsolute method");
   
   be->getBeforeAndAfterNamesAbsolute(-1, DNSName("middle.unit.test."), unhashed, before, after);
   BOOST_CHECK_EQUAL(unhashed.toString(), "middle.");
   BOOST_CHECK_EQUAL(before.toString(), "begin.");
   BOOST_CHECK_EQUAL(after.toString(), "stop.");
}

BOOST_AUTO_TEST_CASE(test_method_setTSIGKey) {
   std::string algorithm, content;
   BOOST_TEST_MESSAGE("Testing setTSIGKey method");
   BOOST_CHECK_MESSAGE(be->setTSIGKey(DNSName("unit.test."),DNSName("hmac-md5."),"kp4/24gyYsEzbuTVJRUMoqGFmN3LYgVDzJ/3oRSP7ys="), "did not return true");
}

BOOST_AUTO_TEST_CASE(test_method_getTSIGKey) {
   DNSName algorithm;
   std::string content;
   BOOST_TEST_MESSAGE("Testing getTSIGKey method");
   be->getTSIGKey(DNSName("unit.test."),&algorithm,&content);
   BOOST_CHECK_EQUAL(algorithm.toString(), "hmac-md5.");
   BOOST_CHECK_EQUAL(content, "kp4/24gyYsEzbuTVJRUMoqGFmN3LYgVDzJ/3oRSP7ys=");
}

BOOST_AUTO_TEST_CASE(test_method_deleteTSIGKey) {
   std::string algorithm, content;
   BOOST_TEST_MESSAGE("Testing deleteTSIGKey method");
   BOOST_CHECK_MESSAGE(be->deleteTSIGKey(DNSName("unit.test.")), "did not return true");
}

BOOST_AUTO_TEST_CASE(test_method_getTSIGKeys) {
   std::vector<struct TSIGKey> keys;
   BOOST_TEST_MESSAGE("Testing getTSIGKeys method");
   be->getTSIGKeys(keys);
   BOOST_CHECK(keys.size() > 0);
   if (keys.size() > 0) {
     BOOST_CHECK_EQUAL(keys[0].name.toString(), "test.");
     BOOST_CHECK_EQUAL(keys[0].algorithm.toString(), "NULL.");
     BOOST_CHECK_EQUAL(keys[0].key, "NULL");
   }
}

BOOST_AUTO_TEST_CASE(test_method_setNotified) {
   BOOST_TEST_MESSAGE("Testing setNotified method");
   be->setNotified(1, 2);
   BOOST_CHECK(true); // we check this on next step
}

BOOST_AUTO_TEST_CASE(test_method_getDomainInfo) {
   DomainInfo di;
   BOOST_TEST_MESSAGE("Testing getDomainInfo method");
   be->getDomainInfo(DNSName("unit.test."), di);
   BOOST_CHECK_EQUAL(di.zone.toString(), "unit.test.");
   BOOST_CHECK_EQUAL(di.serial, 2);
   BOOST_CHECK_EQUAL(di.notified_serial, 2);
   BOOST_CHECK_EQUAL(di.kind, DomainInfo::Native);
   BOOST_CHECK_EQUAL(di.backend, be);
}

BOOST_AUTO_TEST_CASE(test_method_getAllDomains) {
   DomainInfo di;
   BOOST_TEST_MESSAGE("Testing getAllDomains method");
   vector<DomainInfo> result;

   be->getAllDomains(&result, true);

   di = result[0];
   BOOST_CHECK_EQUAL(di.zone.toString(), "unit.test.");
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

   rr.qname = DNSName("example.com.");
   rr.qtype = QType::NS;
   rr.qclass = QClass::IN;
   rr.ttl = 300;
   rr.content = "ns1.example.com.";
   nsset.push_back(rr);
   rr.qname = DNSName("example.com.");
   rr.qtype = QType::NS;
   rr.qclass = QClass::IN;
   rr.ttl = 300;
   rr.content = "ns2.example.com.";
   nsset.push_back(rr);

   BOOST_CHECK(be->superMasterBackend("10.0.0.1", DNSName("example.com."), nsset, NULL, NULL, &dbd));

   // let's see what we got
   BOOST_CHECK_EQUAL(dbd, be);
}

BOOST_AUTO_TEST_CASE(test_method_createSlaveDomain) {
   BOOST_TEST_MESSAGE("Testing createSlaveDomain method");
   BOOST_CHECK(be->createSlaveDomain("10.0.0.1", DNSName("pirate.unit.test."), "", ""));
}

BOOST_AUTO_TEST_CASE(test_method_feedRecord) {
   DNSResourceRecord rr;
   BOOST_TEST_MESSAGE("Testing feedRecord method");
   be->startTransaction(DNSName("example.com."),2);
   rr.qname = DNSName("example.com.");
   rr.qtype = QType::SOA;
   rr.qclass = QClass::IN;
   rr.ttl = 300;
   rr.content = "ns1.example.com. hostmaster.example.com. 2013013441 7200 3600 1209600 300";
   BOOST_CHECK(be->feedRecord(rr, DNSName()));
   rr.qname = DNSName("replace.example.com.");
   rr.qtype = QType::A;
   rr.qclass = QClass::IN;
   rr.ttl = 300;
   rr.content = "127.0.0.1";
   BOOST_CHECK(be->feedRecord(rr, DNSName()));
   be->commitTransaction();
}

BOOST_AUTO_TEST_CASE(test_method_replaceRRSet) {
   be->startTransaction(DNSName("example.com."),2);
   DNSResourceRecord rr;
   std::vector<DNSResourceRecord> rrset;
   BOOST_TEST_MESSAGE("Testing replaceRRSet method");
   rr.qname = DNSName("replace.example.com.");
   rr.qtype = QType::A;
   rr.qclass = QClass::IN;
   rr.ttl = 300;
   rr.content = "1.1.1.1";
   rrset.push_back(rr);
   BOOST_CHECK(be->replaceRRSet(2, DNSName("replace.example.com."), QType(QType::A), rrset));
   be->commitTransaction();
}

BOOST_AUTO_TEST_CASE(test_method_feedEnts) {
   BOOST_TEST_MESSAGE("Testing feedEnts method");
   be->startTransaction(DNSName("example.com."),2);
   map<DNSName, bool> nonterm = boost::assign::map_list_of(DNSName("_udp"), true)(DNSName("_sip._udp"), true);
   BOOST_CHECK(be->feedEnts(2, nonterm));
   be->commitTransaction();
}

BOOST_AUTO_TEST_CASE(test_method_feedEnts3) {
   BOOST_TEST_MESSAGE("Testing feedEnts3 method");
   be->startTransaction(DNSName("example.com"),2);
   NSEC3PARAMRecordContent ns3prc;
   ns3prc.d_iterations=1;
   ns3prc.d_salt="\u00aa\u00bb\u00cc\u00dd";
   map<DNSName, bool> nonterm = boost::assign::map_list_of(DNSName("_udp"), true)(DNSName("_sip._udp"), true);
   BOOST_CHECK(be->feedEnts3(2, DNSName("example.com."), nonterm, ns3prc, 0));
   be->commitTransaction();
}

BOOST_AUTO_TEST_CASE(test_method_abortTransaction) {
   BOOST_TEST_MESSAGE("Testing abortTransaction method");
   be->startTransaction(DNSName("example.com."),2);
   BOOST_CHECK(be->abortTransaction());
}

BOOST_AUTO_TEST_CASE(test_method_directBackendCmd) {
   BOOST_TEST_MESSAGE("Testing directBackendCmd method");
   BOOST_CHECK_EQUAL(be->directBackendCmd("PING 1234"), "PING 1234");
}

BOOST_AUTO_TEST_CASE(test_method_getUpdatedMasters) {
   DomainInfo di;
   BOOST_TEST_MESSAGE("Testing getUpdatedMasters method");
   vector<DomainInfo> result;

   be->getUpdatedMasters(&result);

   BOOST_CHECK(result.size() > 0);

   di = result[0];
   BOOST_CHECK_EQUAL(di.zone.toString(), "master.test.");
   BOOST_CHECK_EQUAL(di.serial, 2);
   BOOST_CHECK_EQUAL(di.notified_serial, 2);
   BOOST_CHECK_EQUAL(di.kind, DomainInfo::Master);
   BOOST_CHECK_EQUAL(di.backend, be);
}

BOOST_AUTO_TEST_SUITE_END();
