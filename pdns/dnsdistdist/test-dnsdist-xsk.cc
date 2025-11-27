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
 * along with this program; if not, see <https://www.gnu.org/licenses/>.
 */
#ifndef BOOST_TEST_DYN_LINK
#define BOOST_TEST_DYN_LINK
#endif

#define BOOST_TEST_NO_MAIN

#include <boost/test/unit_test.hpp>

#include "config.h"
#include "dnsdist-mac-address.hh"
#include "iputils.hh"
#include "xsk.hh"

BOOST_AUTO_TEST_SUITE(test_dnsdist_xsk)

#if defined(HAVE_XSK)

BOOST_AUTO_TEST_CASE(test_XskSocket)
{
  auto itfs = getListOfNetworkInterfaces();
  if (itfs.empty()) {
    /* we won't be able to create a XskSocket without a valid interface name */
    return;
  }
  const auto& itfName = *itfs.begin();
  const uint32_t queueId = 0;
  const std::string path = "/tmp/xsk-test";

  {
    /* not a power of two, should throw */
    BOOST_CHECK_THROW(XskSocket(1000U, itfName, queueId, path), std::runtime_error);
  }

  {
    /* not a valid interface name, should throw */
    BOOST_CHECK_THROW(XskSocket(1024U, "not-an-interface-name", queueId, path), std::runtime_error);
  }

  {
    /* not enough privileges, should throw */
    const size_t numberOfFrames = 1024U;
    BOOST_CHECK_THROW(XskSocket(numberOfFrames, itfName, queueId, path), std::runtime_error);
  }
}

BOOST_AUTO_TEST_CASE(test_XskPacket)
{
  const dnsdist::MacAddress fromMAC{};
  const dnsdist::MacAddress toMAC{0x01, 0x02, 0x03, 0x04, 0x05, 0x06};

  {
    /* empty packet with no room! */
    auto packet = XskPacket(nullptr, 0U, 0U);
    BOOST_CHECK(!packet.parse(false));
    BOOST_CHECK(packet.getFrameOffsetFrom(nullptr) == 0);
  }

  {
    /* IPv4 */
    const ComboAddress fromAddr("192.0.2.1:42");
    const ComboAddress toAddr("192.0.2.2:53");

    /* empty packet but with decent room to grow */
    PacketBuffer payload(XskSocket::getFrameSize());
    auto packet = XskPacket(payload.data(), 0U, payload.size());
    BOOST_CHECK_EQUAL(packet.getFlags(), 0U);
    BOOST_CHECK(packet.getFrameOffsetFrom(payload.data()) == 0);
    BOOST_CHECK(!packet.parse(false));
    BOOST_CHECK_EQUAL(packet.getFrameLen(), 0U);
    BOOST_CHECK_EQUAL(packet.getFlags(), 0U);
    packet.setAddr(fromAddr, fromMAC, toAddr, toMAC);
    BOOST_CHECK_EQUAL(packet.getFlags(), XskPacket::UPDATED);
    BOOST_CHECK_EQUAL(packet.getFromAddr().toStringWithPort(), fromAddr.toStringWithPort());
    BOOST_CHECK_EQUAL(packet.getToAddr().toStringWithPort(), toAddr.toStringWithPort());
    BOOST_CHECK_EQUAL(packet.isIPV6(), fromAddr.isIPv6());
    packet.setPayload(PacketBuffer());
    packet.rewrite();
    BOOST_CHECK_EQUAL(packet.getFlags(), XskPacket::REWRITTEN | XskPacket::UPDATED);

    BOOST_CHECK(packet.parse(false));
    BOOST_CHECK_EQUAL(packet.isIPV6(), fromAddr.isIPv6());
    BOOST_CHECK_EQUAL(packet.getFrameLen(), 42U);
    BOOST_CHECK_EQUAL(packet.getCapacity(), (XskSocket::getFrameSize() - XDP_PACKET_HEADROOM - packet.getFrameLen()));
    BOOST_CHECK_EQUAL(packet.getDataLen(), 0U);
    BOOST_CHECK(packet.getPayloadData() == payload.data() + packet.getFrameLen());
    {
      auto cloned = packet.clonePacketBuffer();
      BOOST_CHECK(cloned.empty());
      auto header = packet.cloneHeaderToPacketBuffer();
      BOOST_CHECK_EQUAL(header.size(), 42U);
      auto newPacket = XskPacket(payload.data(), 0U, payload.size());
      newPacket.setHeader(header);
      BOOST_CHECK_EQUAL(newPacket.getFrameLen(), 42U);
    }

    {
      auto smallPayload = PacketBuffer(packet.getCapacity() - 1U);
      BOOST_CHECK(packet.setPayload(smallPayload));
      BOOST_CHECK_EQUAL(packet.getFlags(), XskPacket::REWRITTEN | XskPacket::UPDATED);
    }

    {
      auto newPacket = XskPacket(payload.data(), 0U, payload.size());
      auto bigPayload = PacketBuffer(newPacket.getCapacity() + 1U);
      BOOST_CHECK_EQUAL(newPacket.getFlags(), 0U);
      /* try to add a payload that is too big for the frame */
      BOOST_CHECK(!newPacket.setPayload(bigPayload));
      BOOST_CHECK_EQUAL(newPacket.getFlags(), 0U);
    }

    {
      auto sendTime = packet.getSendTime();
      BOOST_CHECK_EQUAL(sendTime.tv_sec, 0);
      BOOST_CHECK_EQUAL(sendTime.tv_nsec, 0);
      BOOST_CHECK_EQUAL(packet.getFlags() & XskPacket::Flags::DELAY, 0U);
      /* adding 100 ms */
      packet.addDelay(100U);
      auto newSendTime = packet.getSendTime();
      BOOST_CHECK(sendTime < newSendTime);
      BOOST_CHECK_EQUAL(packet.getFlags() & XskPacket::Flags::DELAY, XskPacket::Flags::DELAY);
    }
  }

  {
    /* IPv6 */
    const ComboAddress fromAddr("[2001:db8::1]:42");
    const ComboAddress toAddr("[2001:db8::2]:53");

    /* empty packet but with decent room to grow */
    PacketBuffer payload(XskSocket::getFrameSize());
    auto packet = XskPacket(payload.data(), 0U, payload.size());
    BOOST_CHECK_EQUAL(packet.getFlags(), 0U);
    BOOST_CHECK(packet.getFrameOffsetFrom(payload.data()) == 0);
    BOOST_CHECK(!packet.parse(false));
    BOOST_CHECK_EQUAL(packet.getFrameLen(), 0U);
    packet.setAddr(fromAddr, fromMAC, toAddr, toMAC);
    BOOST_CHECK_EQUAL(packet.getFromAddr().toStringWithPort(), fromAddr.toStringWithPort());
    BOOST_CHECK_EQUAL(packet.getToAddr().toStringWithPort(), toAddr.toStringWithPort());
    BOOST_CHECK_EQUAL(packet.isIPV6(), fromAddr.isIPv6());
    packet.setPayload(PacketBuffer());
    packet.rewrite();

    BOOST_CHECK(packet.parse(false));
    BOOST_CHECK_EQUAL(packet.isIPV6(), fromAddr.isIPv6());
    BOOST_CHECK_EQUAL(packet.getFrameLen(), 62U);
    BOOST_CHECK_EQUAL(packet.getCapacity(), (XskSocket::getFrameSize() - XDP_PACKET_HEADROOM - packet.getFrameLen()));
    BOOST_CHECK_EQUAL(packet.getDataLen(), 0U);
    BOOST_CHECK(packet.getPayloadData() == payload.data() + packet.getFrameLen());
    {
      auto cloned = packet.clonePacketBuffer();
      BOOST_CHECK(cloned.empty());
      auto header = packet.cloneHeaderToPacketBuffer();
      BOOST_CHECK_EQUAL(header.size(), 62U);
      auto newPacket = XskPacket(payload.data(), 0U, payload.size());
      newPacket.setHeader(header);
      BOOST_CHECK_EQUAL(newPacket.getFrameLen(), 62U);
    }
  }
}

#endif /* HAVE_XSK */

BOOST_AUTO_TEST_SUITE_END();
