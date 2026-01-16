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

#include "config.h"

#include <string>
#include <boost/test/unit_test.hpp>

#include "ednscookies.hh"
#include "iputils.hh"

BOOST_AUTO_TEST_SUITE(test_ednscookie)
BOOST_AUTO_TEST_CASE(test_getEDNSCookiesOptFromString)
{
  std::string cookie;
  EDNSCookiesOpt eco(cookie);
  // Length 0
  BOOST_CHECK(!eco.isWellFormed());

  // Too short
  cookie = "\x12\x34\x56\x78\x90\xab\xcd";
  BOOST_CHECK(!eco.makeFromString(cookie));

  // Correct length client cookie
  cookie = "\x12\x34\x56\x78\x90\xab\xcd\xef";
  BOOST_CHECK(eco.makeFromString(cookie));

  // Too short server cookie
  cookie = "\x12\x34\x56\x78\x90\xab\xcd\xef\x01";
  BOOST_CHECK(!eco.makeFromString(cookie));

  cookie = "\x12\x34\x56\x78\x90\xab\xcd\xef\x12\x34\x56\x78\x90\xab\xcd";
  BOOST_CHECK(!eco.makeFromString(cookie));

  // Have server cookie of correct length
  cookie = "\x12\x34\x56\x78\x90\xab\xcd\xef";
  cookie += cookie; // size 16
  BOOST_CHECK(eco.makeFromString(cookie));

  cookie += cookie; // size 32
  BOOST_CHECK(eco.makeFromString(cookie));

  cookie += "\x12\x34\x56\x78\x90\xab\xcd\xef"; // size 40 (the max)
  BOOST_CHECK(eco.makeFromString(cookie));

  // Cookie total size too long
  cookie += "\x01";
  BOOST_CHECK(!eco.makeFromString(cookie));
}

BOOST_AUTO_TEST_CASE(test_ctor)
{
  std::string cookie;
  auto eco = EDNSCookiesOpt(cookie);
  BOOST_CHECK(!eco.isWellFormed());

  eco = EDNSCookiesOpt("\x12\x34\x56\x78\x90\xab\xcd\xef");
  BOOST_CHECK(eco.isWellFormed());
  BOOST_CHECK_EQUAL(8U, eco.makeOptString().length());
}

#ifdef HAVE_CRYPTO_SHORTHASH
BOOST_AUTO_TEST_CASE(test_createEDNSServerCookie)
{
  auto eco = EDNSCookiesOpt("\x12\x34\x56\x78\x90\xab\xcd\xef");
  ComboAddress remote("192.0.2.2");

  BOOST_CHECK(eco.isWellFormed());

  // wrong keysize (not 128 bits)
  std::string secret = "blablablabla";
  BOOST_CHECK(!eco.makeServerCookie(secret, remote));
  BOOST_CHECK(eco.isWellFormed());
  BOOST_CHECK(!eco.isValid(secret, remote));

  secret = "blablablablablab";
  BOOST_CHECK(eco.makeServerCookie(secret, remote));
  BOOST_CHECK(eco.isWellFormed());
  BOOST_CHECK(eco.isValid(secret, remote));

  EDNSCookiesOpt eco2(eco.makeOptString());
  BOOST_CHECK(!eco2.isValid(secret, ComboAddress("192.0.2.1")));
  BOOST_CHECK(!eco2.isValid("blablablablabla1", remote));
  BOOST_CHECK(eco2.isValid(secret, remote));

  /* very old cookie (epoch) */
  const auto veryOldCookie = EDNSCookiesOpt(std::string("\x12\x34\x56\x78\x90\xab\xcd\xef\x01\x00\x00\x00\x00\x00\x00\x00\xcb\xc9\x38\x5f\xb5\x75\x75\x2a", (8U + 16U)));
  BOOST_CHECK(!veryOldCookie.isValid(secret, remote));
}
#endif

BOOST_AUTO_TEST_SUITE_END()
