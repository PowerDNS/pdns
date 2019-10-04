#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <boost/test/unit_test.hpp>
#include "arguments.hh"
#include "dnswriter.hh"
#include "dnsrecords.hh"
#include "dns_random.hh"
#include "iputils.hh"
#include "recpacketcache.hh"
#include <utility>


BOOST_AUTO_TEST_SUITE(test_recpacketcache_cc)

BOOST_AUTO_TEST_CASE(test_recPacketCacheSimple) {
  RecursorPacketCache rpc;
  string fpacket;
  unsigned int tag=0;
  uint32_t age=0;
  uint32_t qhash=0;
  uint32_t ttd=3600;
  BOOST_CHECK_EQUAL(rpc.size(), 0U);

  ::arg().set("rng")="auto";
  ::arg().set("entropy-source")="/dev/urandom";

  DNSName qname("www.powerdns.com");
  vector<uint8_t> packet;
  DNSPacketWriter pw(packet, qname, QType::A);
  pw.getHeader()->rd=true;
  pw.getHeader()->qr=false;
  pw.getHeader()->id=dns_random_uint16();
  string qpacket((const char*)&packet[0], packet.size());
  pw.startRecord(qname, QType::A, ttd);

  BOOST_CHECK_EQUAL(rpc.getResponsePacket(tag, qpacket, time(nullptr), &fpacket, &age, &qhash), false);
  BOOST_CHECK_EQUAL(rpc.getResponsePacket(tag, qpacket, qname, QType::A, QClass::IN, time(nullptr), &fpacket, &age, &qhash), false);

  ARecordContent ar("127.0.0.1");
  ar.toPacket(pw);
  pw.commit();
  string rpacket((const char*)&packet[0], packet.size());

  rpc.insertResponsePacket(tag, qhash, string(qpacket), qname, QType::A, QClass::IN, string(rpacket), time(0), ttd, Indeterminate, 0, 0, boost::none);
  BOOST_CHECK_EQUAL(rpc.size(), 1U);
  rpc.doPruneTo(0);
  BOOST_CHECK_EQUAL(rpc.size(), 0U);
  rpc.insertResponsePacket(tag, qhash, string(qpacket), qname, QType::A, QClass::IN, string(rpacket), time(0), ttd, Indeterminate, 0, 0, boost::none);
  BOOST_CHECK_EQUAL(rpc.size(), 1U);
  rpc.doWipePacketCache(qname);
  BOOST_CHECK_EQUAL(rpc.size(), 0U);

  rpc.insertResponsePacket(tag, qhash, string(qpacket), qname, QType::A, QClass::IN, string(rpacket), time(0), ttd, Indeterminate, 0, 0, boost::none);
  BOOST_CHECK_EQUAL(rpc.size(), 1U);
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
  pw2.getHeader()->id=dns_random_uint16();
  qpacket.assign((const char*)&packet[0], packet.size());

  found = rpc.getResponsePacket(tag, qpacket, time(nullptr), &fpacket, &age, &qhash);
  BOOST_CHECK_EQUAL(found, false);
  found = rpc.getResponsePacket(tag, qpacket, qname, QType::A, QClass::IN, time(nullptr), &fpacket, &age, &qhash);
  BOOST_CHECK_EQUAL(found, false);

  rpc.doWipePacketCache(DNSName("com"), 0xffff, true);
  BOOST_CHECK_EQUAL(rpc.size(), 0U);
}

BOOST_AUTO_TEST_CASE(test_recPacketCache_Tags) {
  /* Insert a response with tag1, the exact same query with a different tag
     should lead to a miss. Inserting a different response with the second tag
     should not override the first one, and we should get a hit for the
     query with either tags, with the response matching the tag.
  */
  RecursorPacketCache rpc;
  string fpacket;
  const unsigned int tag1=0;
  const unsigned int tag2=42;
  uint32_t age=0;
  uint32_t qhash=0;
  uint32_t temphash=0;
  uint32_t ttd=3600;
  BOOST_CHECK_EQUAL(rpc.size(), 0U);

  ::arg().set("rng")="auto";
  ::arg().set("entropy-source")="/dev/urandom";

  DNSName qname("www.powerdns.com");
  vector<uint8_t> packet;
  DNSPacketWriter pw(packet, qname, QType::A);
  pw.getHeader()->rd=true;
  pw.getHeader()->qr=false;
  pw.getHeader()->id=dns_random_uint16();
  string qpacket(reinterpret_cast<const char*>(&packet[0]), packet.size());
  pw.startRecord(qname, QType::A, ttd);

  /* Both interfaces (with and without the qname/qtype/qclass) should get the same hash */
  BOOST_CHECK_EQUAL(rpc.getResponsePacket(tag1, qpacket, time(nullptr), &fpacket, &age, &qhash), false);
  BOOST_CHECK_EQUAL(rpc.getResponsePacket(tag1, qpacket, qname, QType::A, QClass::IN, time(nullptr), &fpacket, &age, &temphash), false);
  BOOST_CHECK_EQUAL(qhash, temphash);

  /* Different tag, should still get get the same hash, for both interfaces */
  BOOST_CHECK_EQUAL(rpc.getResponsePacket(tag2, qpacket, time(nullptr), &fpacket, &age, &temphash), false);
  BOOST_CHECK_EQUAL(qhash, temphash);
  BOOST_CHECK_EQUAL(rpc.getResponsePacket(tag2, qpacket, qname, QType::A, QClass::IN, time(nullptr), &fpacket, &age, &temphash), false);
  BOOST_CHECK_EQUAL(qhash, temphash);

  {
    ARecordContent ar("127.0.0.1");
    ar.toPacket(pw);
    pw.commit();
  }
  string r1packet(reinterpret_cast<const char*>(&packet[0]), packet.size());

  {
    ARecordContent ar("127.0.0.2");
    ar.toPacket(pw);
    pw.commit();
  }
  string r2packet(reinterpret_cast<const char*>(&packet[0]), packet.size());

  BOOST_CHECK(r1packet != r2packet);

  /* inserting a response for tag1 */
  rpc.insertResponsePacket(tag1, qhash, string(qpacket), qname, QType::A, QClass::IN, string(r1packet), time(0), ttd, Indeterminate, 0, 0, boost::none);
  BOOST_CHECK_EQUAL(rpc.size(), 1U);

  /* inserting a different response for tag2, should not override the first one */
  rpc.insertResponsePacket(tag2, qhash, string(qpacket), qname, QType::A, QClass::IN, string(r2packet), time(0), ttd, Indeterminate, 0, 0, boost::none);
  BOOST_CHECK_EQUAL(rpc.size(), 2U);

  /* remove all responses from the cache */
  rpc.doPruneTo(0);
  BOOST_CHECK_EQUAL(rpc.size(), 0U);

  /* reinsert both */
  rpc.insertResponsePacket(tag1, qhash, string(qpacket), qname, QType::A, QClass::IN, string(r1packet), time(0), ttd, Indeterminate, 0, 0, boost::none);
  BOOST_CHECK_EQUAL(rpc.size(), 1U);

  rpc.insertResponsePacket(tag2, qhash, string(qpacket), qname, QType::A, QClass::IN, string(r2packet), time(0), ttd, Indeterminate, 0, 0, boost::none);
  BOOST_CHECK_EQUAL(rpc.size(), 2U);

  /* remove the responses by qname, should remove both */
  rpc.doWipePacketCache(qname);
  BOOST_CHECK_EQUAL(rpc.size(), 0U);

  /* insert the response for tag1 */
  rpc.insertResponsePacket(tag1, qhash, string(qpacket), qname, QType::A, QClass::IN, string(r1packet), time(0), ttd, Indeterminate, 0, 0, boost::none);
  BOOST_CHECK_EQUAL(rpc.size(), 1U);

  /* we can retrieve it */
  BOOST_CHECK_EQUAL(rpc.getResponsePacket(tag1, qpacket, qname, QType::A, QClass::IN, time(nullptr), &fpacket, &age, &temphash), true);
  BOOST_CHECK_EQUAL(qhash, temphash);
  BOOST_CHECK_EQUAL(fpacket, r1packet);

  /* with both interfaces */
  BOOST_CHECK_EQUAL(rpc.getResponsePacket(tag1, qpacket, time(nullptr), &fpacket, &age, &temphash), true);
  BOOST_CHECK_EQUAL(qhash, temphash);
  BOOST_CHECK_EQUAL(fpacket, r1packet);

  /* but not with the second tag */
  BOOST_CHECK_EQUAL(rpc.getResponsePacket(tag2, qpacket, qname, QType::A, QClass::IN, time(nullptr), &fpacket, &age, &temphash), false);
  /* we should still get the same hash */
  BOOST_CHECK_EQUAL(temphash, qhash);

  /* adding a response for the second tag */
  rpc.insertResponsePacket(tag2, qhash, string(qpacket), qname, QType::A, QClass::IN, string(r2packet), time(0), ttd, Indeterminate, 0, 0, boost::none);
  BOOST_CHECK_EQUAL(rpc.size(), 2U);

  /* We still get the correct response for the first tag */
  BOOST_CHECK_EQUAL(rpc.getResponsePacket(tag1, qpacket, time(nullptr), &fpacket, &age, &temphash), true);
  BOOST_CHECK_EQUAL(qhash, temphash);
  BOOST_CHECK_EQUAL(fpacket, r1packet);

  BOOST_CHECK_EQUAL(rpc.getResponsePacket(tag1, qpacket, qname, QType::A, QClass::IN, time(nullptr), &fpacket, &age, &temphash), true);
  BOOST_CHECK_EQUAL(qhash, temphash);
  BOOST_CHECK_EQUAL(fpacket, r1packet);

  /* and the correct response for the second tag */
  BOOST_CHECK_EQUAL(rpc.getResponsePacket(tag2, qpacket, time(nullptr), &fpacket, &age, &temphash), true);
  BOOST_CHECK_EQUAL(qhash, temphash);
  BOOST_CHECK_EQUAL(fpacket, r2packet);

  BOOST_CHECK_EQUAL(rpc.getResponsePacket(tag2, qpacket, qname, QType::A, QClass::IN, time(nullptr), &fpacket, &age, &temphash), true);
  BOOST_CHECK_EQUAL(qhash, temphash);
  BOOST_CHECK_EQUAL(fpacket, r2packet);
}

BOOST_AUTO_TEST_SUITE_END()
