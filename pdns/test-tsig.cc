
/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2013 - 2015  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2
    as published by the Free Software Foundation

    Additionally, the license of this program contains a special
    exception which allows to distribute the program in binary form when
    it is linked against OpenSSL.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <boost/test/unit_test.hpp>

#include "dnssecinfra.hh"
#include "dnswriter.hh"
#include "misc.hh"
#include "tsigverifier.hh"

BOOST_AUTO_TEST_SUITE(test_tsig)

static vector<uint8_t> generateTSIGQuery(const DNSName& qname, const DNSName& tsigName, const DNSName& tsigAlgo, const string& tsigSecret, uint16_t fudge=300, time_t tsigTime=time(nullptr))
{
  vector<uint8_t> packet;
  DNSPacketWriter pw(packet, qname, QType::A);
  pw.getHeader()->qr=0;
  pw.getHeader()->rd=0;
  pw.getHeader()->id=42;
  pw.startRecord(qname, QType::A);
  pw.xfr32BitInt(0x01020304);
  pw.addOpt(512, 0, 0);
  pw.commit();

  TSIGTriplet tt;
  tt.name = tsigName;
  tt.algo = tsigAlgo;
  tt.secret = tsigSecret;

  TSIGHashEnum the;
  BOOST_REQUIRE(getTSIGHashEnum(tt.algo, the));

  TSIGRecordContent trc;
  trc.d_algoName = getTSIGAlgoName(the);
  trc.d_time = tsigTime;
  trc.d_fudge = fudge;
  trc.d_origID = ntohs(pw.getHeader()->id);
  trc.d_eRcode = 0;

  addTSIG(pw, trc, tt.name, tt.secret, "", false);
  return packet;
}

static void checkTSIG(const DNSName& tsigName, const DNSName& tsigAlgo, const string& tsigSecret, const vector<uint8_t>& packet, const string* overrideMac=nullptr, uint16_t* overrideExtendedRCode=nullptr, uint16_t* overrideOrigID=nullptr)
{
  string packetStr(reinterpret_cast<const char*>(packet.data()), packet.size());
  MOADNSParser mdp(true, packetStr);

  bool tsigFound = false;
  string theirMac;
  DNSName keyName;
  TSIGRecordContent trc;

  for(const auto& answer: mdp.d_answers) {
    if(answer.first.d_type == QType::TSIG) {
      BOOST_CHECK_EQUAL(answer.first.d_place, DNSResourceRecord::ADDITIONAL);
      BOOST_CHECK_EQUAL(answer.first.d_class, QClass::ANY);
      BOOST_CHECK_EQUAL(answer.first.d_ttl, 0U);
      BOOST_CHECK_EQUAL(tsigFound, false);

      shared_ptr<TSIGRecordContent> rectrc = getRR<TSIGRecordContent>(answer.first);
      if (rectrc) {
        trc = *rectrc;
        theirMac = rectrc->d_mac;
        keyName = answer.first.d_name;
        tsigFound = true;
      }
    }
  }

  if (overrideMac) {
    theirMac = *overrideMac;
  }

  if (overrideOrigID) {
    trc.d_origID = *overrideOrigID;
  }

  if (overrideExtendedRCode) {
    trc.d_eRcode = *overrideExtendedRCode;
  }

  BOOST_REQUIRE(tsigFound);
  TSIGTriplet tt;
  tt.name = tsigName;
  tt.algo = tsigAlgo;
  tt.secret = tsigSecret;

  BOOST_CHECK(validateTSIG(packetStr, mdp.getTSIGPos(), tt, trc, "", theirMac, false));
}

BOOST_AUTO_TEST_CASE(test_TSIG_valid) {
  DNSName tsigName("tsig.name");
  DNSName tsigAlgo("HMAC-MD5.SIG-ALG.REG.INT");
  DNSName qname("test.valid.tsig");
  string tsigSecret("verysecret");

  vector<uint8_t> packet = generateTSIGQuery(qname, tsigName, tsigAlgo, tsigSecret);

  checkTSIG(tsigName, tsigAlgo, tsigSecret, packet);}


BOOST_AUTO_TEST_CASE(test_TSIG_different_case_algo) {
  DNSName tsigName("tsig.name");
  DNSName tsigAlgo("HMAC-MD5.SIG-ALG.REG.INT");
  DNSName qname("test.valid.tsig");
  string tsigSecret("verysecret");

  vector<uint8_t> packet = generateTSIGQuery(qname, tsigName, tsigAlgo, tsigSecret);

  checkTSIG(tsigName, tsigAlgo.makeLowerCase(), tsigSecret, packet);
}

BOOST_AUTO_TEST_CASE(test_TSIG_different_name_same_algo) {
  DNSName tsigName("tsig.name");
  DNSName tsigAlgo("HMAC-MD5.SIG-ALG.REG.INT");
  DNSName qname("test.valid.tsig");
  string tsigSecret("verysecret");

  vector<uint8_t> packet = generateTSIGQuery(qname, tsigName, tsigAlgo, tsigSecret);

  checkTSIG(tsigName, DNSName("hmac-md5."), tsigSecret, packet);
}

BOOST_AUTO_TEST_CASE(test_TSIG_bad_key_name) {
  DNSName tsigName("tsig.name");
  DNSName tsigAlgo("HMAC-MD5.SIG-ALG.REG.INT");
  DNSName qname("test.valid.tsig");
  string tsigSecret("verysecret");

  vector<uint8_t> packet = generateTSIGQuery(qname, tsigName, tsigAlgo, tsigSecret);

  BOOST_CHECK_THROW(checkTSIG(DNSName("another.tsig.key.name"), tsigAlgo, tsigSecret, packet), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(test_TSIG_bad_algo) {
  DNSName tsigName("tsig.name");
  DNSName tsigAlgo("HMAC-MD5.SIG-ALG.REG.INT");
  DNSName qname("test.valid.tsig");
  string tsigSecret("verysecret");

  vector<uint8_t> packet = generateTSIGQuery(qname, tsigName, tsigAlgo, tsigSecret);

  BOOST_CHECK_THROW(checkTSIG(tsigName, DNSName("hmac-sha512."), tsigSecret, packet), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(test_TSIG_bad_secret) {
  DNSName tsigName("tsig.name");
  DNSName tsigAlgo("HMAC-MD5.SIG-ALG.REG.INT");
  DNSName qname("test.valid.tsig");
  string tsigSecret("verysecret");

  vector<uint8_t> packet = generateTSIGQuery(qname, tsigName, tsigAlgo, tsigSecret);

  BOOST_CHECK_THROW(checkTSIG(tsigName, tsigAlgo, "bad secret", packet), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(test_TSIG_bad_ercode) {
  DNSName tsigName("tsig.name");
  DNSName tsigAlgo("HMAC-MD5.SIG-ALG.REG.INT");
  DNSName qname("test.valid.tsig");
  string tsigSecret("verysecret");

  vector<uint8_t> packet = generateTSIGQuery(qname, tsigName, tsigAlgo, tsigSecret);
  uint16_t badERcode = 1;

  BOOST_CHECK_THROW(checkTSIG(tsigName, tsigAlgo, tsigSecret, packet, nullptr, &badERcode), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(test_TSIG_bad_origID) {
  DNSName tsigName("tsig.name");
  DNSName tsigAlgo("HMAC-MD5.SIG-ALG.REG.INT");
  DNSName qname("test.valid.tsig");
  string tsigSecret("verysecret");

  vector<uint8_t> packet = generateTSIGQuery(qname, tsigName, tsigAlgo, tsigSecret);
  uint16_t badOrigID = 1;

  BOOST_CHECK_THROW(checkTSIG(tsigName, tsigAlgo, tsigSecret, packet, nullptr, nullptr, &badOrigID), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(test_TSIG_bad_mac) {
  DNSName tsigName("tsig.name");
  DNSName tsigAlgo("HMAC-MD5.SIG-ALG.REG.INT");
  DNSName qname("test.valid.tsig");
  string tsigSecret("verysecret");

  vector<uint8_t> packet = generateTSIGQuery(qname, tsigName, tsigAlgo, tsigSecret);

  string badMac = "badmac";
  BOOST_CHECK_THROW(checkTSIG(tsigName, tsigAlgo, tsigSecret, packet, &badMac), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(test_TSIG_signature_expired) {
  DNSName tsigName("tsig.name");
  DNSName tsigAlgo("HMAC-MD5.SIG-ALG.REG.INT");
  DNSName qname("test.valid.tsig");
  string tsigSecret("verysecret");

  vector<uint8_t> packet = generateTSIGQuery(qname, tsigName, tsigAlgo, tsigSecret, 5, time(nullptr) - 10);

  BOOST_CHECK_THROW(checkTSIG(tsigName, tsigAlgo, tsigSecret, packet), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(test_TSIG_signature_too_far_in_the_future) {
  DNSName tsigName("tsig.name");
  DNSName tsigAlgo("HMAC-MD5.SIG-ALG.REG.INT");
  DNSName qname("test.valid.tsig");
  string tsigSecret("verysecret");

  vector<uint8_t> packet = generateTSIGQuery(qname, tsigName, tsigAlgo, tsigSecret, 5, time(nullptr) + 20);

  BOOST_CHECK_THROW(checkTSIG(tsigName, tsigAlgo, tsigSecret, packet), std::runtime_error);
}

BOOST_AUTO_TEST_SUITE_END();
