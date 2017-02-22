#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <boost/test/unit_test.hpp>
#include "dnswriter.hh"
#include "dnsrecords.hh"
#include "dns_random.hh"
#include "iputils.hh"
#include "recpacketcache.hh"
#include <utility>


BOOST_AUTO_TEST_SUITE(recpacketcache_cc)

BOOST_AUTO_TEST_CASE(test_recPacketCacheSimple) {
  RecursorPacketCache rpc;
  string fpacket;
  int tag=0;
  uint32_t age=0;
  uint32_t qhash=0;
  uint32_t ttd=3600;
  BOOST_CHECK_EQUAL(rpc.size(), 0);

  DNSName qname("www.powerdns.com");
  vector<uint8_t> packet;
  DNSPacketWriter pw(packet, qname, QType::A);
  pw.getHeader()->rd=true;
  pw.getHeader()->qr=false;
  pw.getHeader()->id=random();
  string qpacket((const char*)&packet[0], packet.size());
  pw.startRecord(qname, QType::A, ttd);

  BOOST_CHECK_EQUAL(rpc.getResponsePacket(tag, qpacket, time(nullptr), &fpacket, &age, &qhash), false);
  BOOST_CHECK_EQUAL(rpc.getResponsePacket(tag, qpacket, qname, QType::A, QClass::IN, time(nullptr), &fpacket, &age, &qhash), false);

  ARecordContent ar("127.0.0.1");
  ar.toPacket(pw);
  pw.commit();
  string rpacket((const char*)&packet[0], packet.size());

  rpc.insertResponsePacket(tag, qhash, qname, QType::A, QClass::IN, rpacket, time(0), ttd);
  BOOST_CHECK_EQUAL(rpc.size(), 1);
  rpc.doPruneTo(0);
  BOOST_CHECK_EQUAL(rpc.size(), 0);
  rpc.insertResponsePacket(tag, qhash, qname, QType::A, QClass::IN, rpacket, time(0), ttd);
  BOOST_CHECK_EQUAL(rpc.size(), 1);
  rpc.doWipePacketCache(qname);
  BOOST_CHECK_EQUAL(rpc.size(), 0);

  rpc.insertResponsePacket(tag, qhash, qname, QType::A, QClass::IN, rpacket, time(0), ttd);
  uint32_t qhash2 = 0;
  bool found = rpc.getResponsePacket(tag, qpacket, time(nullptr), &fpacket, &age, &qhash2);
  BOOST_CHECK_EQUAL(found, true);
  BOOST_CHECK_EQUAL(qhash, qhash2);
  BOOST_CHECK_EQUAL(fpacket, rpacket);
  found = rpc.getResponsePacket(tag, qpacket, qname, QType::A, QClass::IN, time(nullptr), &fpacket, &age, &qhash2);
  BOOST_CHECK_EQUAL(found, true);
  BOOST_CHECK_EQUAL(qhash, qhash2);
  BOOST_CHECK_EQUAL(fpacket, rpacket);

  packet.clear();
  qname+=DNSName("co.uk");
  DNSPacketWriter pw2(packet, qname, QType::A);

  pw2.getHeader()->rd=true;
  pw2.getHeader()->qr=false;
  pw2.getHeader()->id=random();
  qpacket.assign((const char*)&packet[0], packet.size());

  found = rpc.getResponsePacket(tag, qpacket, time(nullptr), &fpacket, &age, &qhash);
  BOOST_CHECK_EQUAL(found, false);
  found = rpc.getResponsePacket(tag, qpacket, qname, QType::A, QClass::IN, time(nullptr), &fpacket, &age, &qhash);
  BOOST_CHECK_EQUAL(found, false);

  rpc.doWipePacketCache(DNSName("com"), 0xffff, true);
  BOOST_CHECK_EQUAL(rpc.size(), 0);
} 

BOOST_AUTO_TEST_SUITE_END()
