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

#include <boost/test/unit_test.hpp>

#include "dns.hh"

BOOST_AUTO_TEST_SUITE(test_dnscc)

BOOST_AUTO_TEST_CASE(test_rcode)
{
  BOOST_CHECK_EQUAL(RCode::to_s(16), "ErrOutOfRange");
  BOOST_CHECK_EQUAL(RCode::to_short_s(16), "ErrOutOfRange");

  for (uint8_t idx = 0; idx <= RCode::NotZone; idx++) {
    auto long_s = RCode::to_s(idx);
    BOOST_CHECK(long_s.size() > 0);
    auto short_s = RCode::to_short_s(idx);
    auto rcode = RCode::from_short(short_s);
    BOOST_CHECK(rcode);
    BOOST_CHECK_EQUAL(*rcode, idx);
  }

  BOOST_CHECK_EQUAL(RCode::to_s(RCode::NotZone + 1), "Err#11");
  BOOST_CHECK(!RCode::from_short("badcookie"));
}

BOOST_AUTO_TEST_CASE(test_ercode)
{
  for (uint16_t idx = ERCode::BADVERS; idx <= ERCode::BADCOOKIE; idx++) {
    auto long_s = ERCode::to_s(idx);
    BOOST_CHECK(long_s.size() > 0);
    auto short_s = ERCode::to_short_s(idx);
    auto ercode = ERCode::from_short(short_s);
    BOOST_CHECK(ercode);
    BOOST_CHECK_EQUAL(*ercode, idx);
  }

  BOOST_CHECK_EQUAL(ERCode::to_s(ERCode::BADCOOKIE + 1), "Err#24");
}

BOOST_AUTO_TEST_CASE(test_opcode)
{
  for (uint8_t idx = Opcode::Query; idx <= Opcode::Update; idx++) {
    auto long_s = Opcode::to_s(idx);
    BOOST_CHECK(long_s.size() > 0);
  }

  BOOST_CHECK_EQUAL(Opcode::to_s(Opcode::Update + 1), std::to_string(Opcode::Update + 1));
}

BOOST_AUTO_TEST_CASE(test_resource_record_place)
{
  for (uint8_t idx = DNSResourceRecord::Place::QUESTION; idx <= DNSResourceRecord::Place::ADDITIONAL; idx++) {
    auto long_s = DNSResourceRecord::placeString(idx);
    BOOST_CHECK(long_s.size() > 0);
  }

  BOOST_CHECK_EQUAL(DNSResourceRecord::placeString(DNSResourceRecord::Place::ADDITIONAL + 1), "?");
}

BOOST_AUTO_TEST_SUITE_END()
