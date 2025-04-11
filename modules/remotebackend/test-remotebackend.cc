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
#ifndef BOOST_TEST_DYN_LINK
#define BOOST_TEST_DYN_LINK
#endif

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

extern std::unique_ptr<DNSBackend> backendUnderTest;

BOOST_AUTO_TEST_SUITE(test_remotebackend_so)

BOOST_AUTO_TEST_CASE(test_method_lookup)
{
  BOOST_TEST_MESSAGE("Testing lookup method");
  DNSResourceRecord resourceRecord;
  backendUnderTest->lookup(QType(QType::SOA), DNSName("unit.test."));
  // then try to get()
  BOOST_CHECK(backendUnderTest->get(resourceRecord)); // and this should be TRUE.
  // then we check rr contains what we expect
  BOOST_CHECK_EQUAL(resourceRecord.qname.toString(), "unit.test.");
  BOOST_CHECK_MESSAGE(resourceRecord.qtype == QType::SOA, "returned qtype was not SOA");
  BOOST_CHECK_EQUAL(resourceRecord.content, "ns.unit.test. hostmaster.unit.test. 1 2 3 4 5");
  BOOST_CHECK_EQUAL(resourceRecord.ttl, 300);
}

BOOST_AUTO_TEST_CASE(test_method_lookup_empty)
{
  BOOST_TEST_MESSAGE("Testing lookup method with empty result");
  DNSResourceRecord resourceRecord;
  backendUnderTest->lookup(QType(QType::SOA), DNSName("empty.unit.test."));
  // then try to get()
  BOOST_CHECK(!backendUnderTest->get(resourceRecord)); // and this should be FALSE
}

BOOST_AUTO_TEST_CASE(test_method_list)
{
  int record_count = 0;
  DNSResourceRecord resourceRecord;

  BOOST_TEST_MESSAGE("Testing list method");
  backendUnderTest->list(ZoneName("unit.test."), -1);
  while (backendUnderTest->get(resourceRecord)) {
    record_count++;
  }

  BOOST_CHECK_EQUAL(record_count, 5); // number of records our test domain has
}

BOOST_AUTO_TEST_CASE(test_method_doesDNSSEC)
{
  BOOST_TEST_MESSAGE("Testing doesDNSSEC method");
  BOOST_CHECK(backendUnderTest->doesDNSSEC()); // should be true
}

BOOST_AUTO_TEST_CASE(test_method_setDomainMetadata)
{
  std::vector<std::string> meta;
  meta.emplace_back("VALUE");
  BOOST_TEST_MESSAGE("Testing setDomainMetadata method");
  BOOST_CHECK(backendUnderTest->setDomainMetadata(ZoneName("unit.test."), "TEST", meta));
}

BOOST_AUTO_TEST_CASE(test_method_alsoNotifies)
{
  BOOST_CHECK(backendUnderTest->setDomainMetadata(ZoneName("unit.test."), "ALSO-NOTIFY", {"192.0.2.1"}));
  std::set<std::string> alsoNotifies;
  BOOST_TEST_MESSAGE("Testing alsoNotifies method");
  backendUnderTest->alsoNotifies(ZoneName("unit.test."), &alsoNotifies);
  BOOST_CHECK_EQUAL(alsoNotifies.size(), 1);
  if (!alsoNotifies.empty()) {
    BOOST_CHECK_EQUAL(alsoNotifies.count("192.0.2.1"), 1);
  }
  BOOST_CHECK(backendUnderTest->setDomainMetadata(ZoneName("unit.test."), "ALSO-NOTIFY", std::vector<std::string>()));
}

BOOST_AUTO_TEST_CASE(test_method_getDomainMetadata)
{
  std::vector<std::string> meta;
  BOOST_TEST_MESSAGE("Testing getDomainMetadata method");
  backendUnderTest->getDomainMetadata(ZoneName("unit.test."), "TEST", meta);
  BOOST_CHECK_EQUAL(meta.size(), 1);
  // in case we got more than one value, which would be unexpected
  // but not fatal
  if (!meta.empty()) {
    BOOST_CHECK_EQUAL(meta[0], "VALUE");
  }
}

BOOST_AUTO_TEST_CASE(test_method_getAllDomainMetadata)
{
  std::map<std::string, std::vector<std::string>> meta;
  BOOST_TEST_MESSAGE("Testing getAllDomainMetadata method");
  backendUnderTest->getAllDomainMetadata(ZoneName("unit.test."), meta);
  BOOST_CHECK_EQUAL(meta.size(), 1);
  // in case we got more than one value, which would be unexpected
  // but not fatal
  if (!meta.empty()) {
    BOOST_CHECK_EQUAL(meta["TEST"][0], "VALUE");
  }
}

BOOST_AUTO_TEST_CASE(test_method_addDomainKey)
{
  BOOST_TEST_MESSAGE("Testing addDomainKey method");
  int64_t keyID = 0;
  backendUnderTest->addDomainKey(ZoneName("unit.test."), k1, keyID);
  BOOST_CHECK_EQUAL(keyID, 1);
  backendUnderTest->addDomainKey(ZoneName("unit.test."), k2, keyID);
  BOOST_CHECK_EQUAL(keyID, 2);
}

BOOST_AUTO_TEST_CASE(test_method_getDomainKeys)
{
  std::vector<DNSBackend::KeyData> keys;
  BOOST_TEST_MESSAGE("Testing getDomainKeys method");
  // we expect to get two keys
  backendUnderTest->getDomainKeys(ZoneName("unit.test."), keys);
  BOOST_CHECK_EQUAL(keys.size(), 2);
  // in case we got more than 2 keys, which would be unexpected
  // but not fatal
  if (keys.size() > 1) {
    // check that we have two keys
    for (DNSBackend::KeyData& keyData : keys) {
      BOOST_CHECK(keyData.id > 0);
      BOOST_CHECK(keyData.flags == 256 || keyData.flags == 257);
      BOOST_CHECK(keyData.active == true);
      BOOST_CHECK(keyData.published == true);
      BOOST_CHECK(keyData.content.size() > 500);
    }
  }
}

BOOST_AUTO_TEST_CASE(test_method_deactivateDomainKey)
{
  BOOST_TEST_MESSAGE("Testing deactivateDomainKey method");
  BOOST_CHECK(backendUnderTest->deactivateDomainKey(ZoneName("unit.test."), 1));
}

BOOST_AUTO_TEST_CASE(test_method_activateDomainKey)
{
  BOOST_TEST_MESSAGE("Testing activateDomainKey method");
  BOOST_CHECK(backendUnderTest->activateDomainKey(ZoneName("unit.test."), 1));
}

BOOST_AUTO_TEST_CASE(test_method_removeDomainKey)
{
  BOOST_CHECK(backendUnderTest->removeDomainKey(ZoneName("unit.test."), 2));
  BOOST_CHECK(backendUnderTest->removeDomainKey(ZoneName("unit.test."), 1));
}

BOOST_AUTO_TEST_CASE(test_method_getBeforeAndAfterNamesAbsolute)
{
  DNSName unhashed;
  DNSName before;
  DNSName after;
  BOOST_TEST_MESSAGE("Testing getBeforeAndAfterNamesAbsolute method");

  backendUnderTest->getBeforeAndAfterNamesAbsolute(1, DNSName("middle.unit.test."), unhashed, before, after);
  BOOST_CHECK_EQUAL(unhashed.toString(), "middle.");
  BOOST_CHECK_EQUAL(before.toString(), "begin.");
  BOOST_CHECK_EQUAL(after.toString(), "stop.");
}

BOOST_AUTO_TEST_CASE(test_method_setTSIGKey)
{
  std::string algorithm;
  std::string content;
  BOOST_TEST_MESSAGE("Testing setTSIGKey method");
  BOOST_CHECK_MESSAGE(backendUnderTest->setTSIGKey(DNSName("unit.test."), DNSName("hmac-md5."), "kp4/24gyYsEzbuTVJRUMoqGFmN3LYgVDzJ/3oRSP7ys="), "did not return true");
}

BOOST_AUTO_TEST_CASE(test_method_getTSIGKey)
{
  DNSName algorithm;
  std::string content;
  BOOST_TEST_MESSAGE("Testing getTSIGKey method");
  backendUnderTest->getTSIGKey(DNSName("unit.test."), algorithm, content);
  BOOST_CHECK_EQUAL(algorithm.toString(), "hmac-md5.");
  BOOST_CHECK_EQUAL(content, "kp4/24gyYsEzbuTVJRUMoqGFmN3LYgVDzJ/3oRSP7ys=");
}

BOOST_AUTO_TEST_CASE(test_method_deleteTSIGKey)
{
  std::string algorithm;
  std::string content;
  BOOST_TEST_MESSAGE("Testing deleteTSIGKey method");
  BOOST_CHECK_MESSAGE(backendUnderTest->deleteTSIGKey(DNSName("unit.test.")), "did not return true");
}

BOOST_AUTO_TEST_CASE(test_method_getTSIGKeys)
{
  std::vector<struct TSIGKey> keys;
  BOOST_TEST_MESSAGE("Testing getTSIGKeys method");
  backendUnderTest->getTSIGKeys(keys);
  BOOST_CHECK(!keys.empty());
  if (!keys.empty()) {
    BOOST_CHECK_EQUAL(keys[0].name.toString(), "test.");
    BOOST_CHECK_EQUAL(keys[0].algorithm.toString(), "NULL.");
    BOOST_CHECK_EQUAL(keys[0].key, "NULL");
  }
}

BOOST_AUTO_TEST_CASE(test_method_setNotified)
{
  BOOST_TEST_MESSAGE("Testing setNotified method");
  backendUnderTest->setNotified(1, 2);
  BOOST_CHECK(true); // we check this on next step
}

BOOST_AUTO_TEST_CASE(test_method_getDomainInfo)
{
  DomainInfo domainInfo;
  BOOST_TEST_MESSAGE("Testing getDomainInfo method");
  backendUnderTest->getDomainInfo(ZoneName("unit.test."), domainInfo);
  BOOST_CHECK_EQUAL(domainInfo.zone.toString(), "unit.test.");
  BOOST_CHECK_EQUAL(domainInfo.serial, 2);
  BOOST_CHECK_EQUAL(domainInfo.notified_serial, 2);
  BOOST_CHECK_EQUAL(domainInfo.kind, DomainInfo::Native);
  BOOST_CHECK_EQUAL(domainInfo.backend, backendUnderTest.get());
}

BOOST_AUTO_TEST_CASE(test_method_getAllDomains)
{
  DomainInfo domainInfo;
  BOOST_TEST_MESSAGE("Testing getAllDomains method");
  vector<DomainInfo> result;

  backendUnderTest->getAllDomains(&result, true, true);

  BOOST_REQUIRE(!result.empty());
  domainInfo = result.at(0);
  BOOST_CHECK_EQUAL(domainInfo.zone.toString(), "unit.test.");
  BOOST_CHECK_EQUAL(domainInfo.serial, 2);
  BOOST_CHECK_EQUAL(domainInfo.notified_serial, 2);
  BOOST_CHECK_EQUAL(domainInfo.kind, DomainInfo::Native);
  BOOST_CHECK_EQUAL(domainInfo.backend, backendUnderTest.get());
}

BOOST_AUTO_TEST_CASE(test_method_autoPrimaryBackend)
{
  DNSResourceRecord resourceRecord;
  std::vector<DNSResourceRecord> nsset;
  DNSBackend* dbd = nullptr;
  BOOST_TEST_MESSAGE("Testing autoPrimaryBackend method");

  resourceRecord.qname = DNSName("example.com.");
  resourceRecord.qtype = QType::NS;
  resourceRecord.qclass = QClass::IN;
  resourceRecord.ttl = 300;
  resourceRecord.content = "ns1.example.com.";
  nsset.push_back(resourceRecord);
  resourceRecord.qname = DNSName("example.com.");
  resourceRecord.qtype = QType::NS;
  resourceRecord.qclass = QClass::IN;
  resourceRecord.ttl = 300;
  resourceRecord.content = "ns2.example.com.";
  nsset.push_back(resourceRecord);

  BOOST_CHECK(backendUnderTest->autoPrimaryBackend("10.0.0.1", ZoneName("example.com."), nsset, nullptr, nullptr, &dbd));

  // let's see what we got
  BOOST_CHECK_EQUAL(dbd, backendUnderTest.get());
}

BOOST_AUTO_TEST_CASE(test_method_createSecondaryDomain)
{
  BOOST_TEST_MESSAGE("Testing createSecondaryDomain method");
  BOOST_CHECK(backendUnderTest->createSecondaryDomain("10.0.0.1", ZoneName("pirate.unit.test."), "", ""));
}

BOOST_AUTO_TEST_CASE(test_method_feedRecord)
{
  DNSResourceRecord resourceRecord;
  BOOST_TEST_MESSAGE("Testing feedRecord method");
  backendUnderTest->startTransaction(ZoneName("example.com."), 3);
  resourceRecord.qname = DNSName("example.com.");
  resourceRecord.qtype = QType::SOA;
  resourceRecord.qclass = QClass::IN;
  resourceRecord.ttl = 300;
  resourceRecord.content = "ns1.example.com. hostmaster.example.com. 2013013441 7200 3600 1209600 300";
  BOOST_CHECK(backendUnderTest->feedRecord(resourceRecord, DNSName()));
  resourceRecord.qname = DNSName("replace.example.com.");
  resourceRecord.qtype = QType::A;
  resourceRecord.qclass = QClass::IN;
  resourceRecord.ttl = 300;
  resourceRecord.content = "127.0.0.1";
  BOOST_CHECK(backendUnderTest->feedRecord(resourceRecord, DNSName()));
  backendUnderTest->commitTransaction();
}

BOOST_AUTO_TEST_CASE(test_method_replaceRRSet)
{
  backendUnderTest->startTransaction(ZoneName("example.com."), 3);
  DNSResourceRecord resourceRecord;
  std::vector<DNSResourceRecord> rrset;
  BOOST_TEST_MESSAGE("Testing replaceRRSet method");
  resourceRecord.qname = DNSName("replace.example.com.");
  resourceRecord.qtype = QType::A;
  resourceRecord.qclass = QClass::IN;
  resourceRecord.ttl = 300;
  resourceRecord.content = "1.1.1.1";
  rrset.push_back(resourceRecord);
  BOOST_CHECK(backendUnderTest->replaceRRSet(2, DNSName("replace.example.com."), QType(QType::A), rrset));
  backendUnderTest->commitTransaction();
}

BOOST_AUTO_TEST_CASE(test_method_feedEnts)
{
  BOOST_TEST_MESSAGE("Testing feedEnts method");
  backendUnderTest->startTransaction(ZoneName("example.com."), 3);
  map<DNSName, bool> nonterm = boost::assign::map_list_of(DNSName("_udp"), true)(DNSName("_sip._udp"), true);
  BOOST_CHECK(backendUnderTest->feedEnts(2, nonterm));
  backendUnderTest->commitTransaction();
}

BOOST_AUTO_TEST_CASE(test_method_feedEnts3)
{
  BOOST_TEST_MESSAGE("Testing feedEnts3 method");
  backendUnderTest->startTransaction(ZoneName("example.com"), 3);
  NSEC3PARAMRecordContent ns3prc;
  ns3prc.d_iterations = 1;
  ns3prc.d_salt = "\u00aa\u00bb\u00cc\u00dd";
  map<DNSName, bool> nonterm = boost::assign::map_list_of(DNSName("_udp"), true)(DNSName("_sip._udp"), true);
  BOOST_CHECK(backendUnderTest->feedEnts3(2, DNSName("example.com."), nonterm, ns3prc, 0));
  backendUnderTest->commitTransaction();
}

BOOST_AUTO_TEST_CASE(test_method_abortTransaction)
{
  BOOST_TEST_MESSAGE("Testing abortTransaction method");
  backendUnderTest->startTransaction(ZoneName("example.com."), 3);
  BOOST_CHECK(backendUnderTest->abortTransaction());
}

BOOST_AUTO_TEST_CASE(test_method_directBackendCmd)
{
  BOOST_TEST_MESSAGE("Testing directBackendCmd method");
  BOOST_CHECK_EQUAL(backendUnderTest->directBackendCmd("PING 1234"), "PING 1234");
}

BOOST_AUTO_TEST_CASE(test_method_getUpdatedPrimaries)
{
  DomainInfo domainInfo;
  BOOST_TEST_MESSAGE("Testing getUpdatedPrimaries method");
  vector<DomainInfo> result;
  std::unordered_set<DNSName> catalogs;
  CatalogHashMap hashes;

  backendUnderTest->getUpdatedPrimaries(result, catalogs, hashes);

  BOOST_REQUIRE(!result.empty());

  domainInfo = result.at(0);
  BOOST_CHECK_EQUAL(domainInfo.zone.toString(), "master.test.");
  BOOST_CHECK_EQUAL(domainInfo.serial, 2);
  BOOST_CHECK_EQUAL(domainInfo.notified_serial, 2);
  BOOST_CHECK_EQUAL(domainInfo.kind, DomainInfo::Primary);
  BOOST_CHECK_EQUAL(domainInfo.backend, backendUnderTest.get());
}

BOOST_AUTO_TEST_SUITE_END();
