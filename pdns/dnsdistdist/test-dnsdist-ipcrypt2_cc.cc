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
#ifdef HAVE_IPCRYPT2

#ifndef BOOST_TEST_DYN_LINK
#define BOOST_TEST_DYN_LINK
#include "iputils.hh"
#include <boost/test/tools/old/interface.hpp>
#include <boost/test/unit_test_suite.hpp>
#include <stdexcept>
#endif

#define BOOST_TEST_NO_MAIN

#include <boost/test/unit_test.hpp>

#include "dnsdist-ipcrypt2.hh"

BOOST_AUTO_TEST_SUITE(test_dnsdist_ipcrypt2_cc)

BOOST_AUTO_TEST_CASE(pfx_success)
{
  auto ipcrypt = pdns::ipcrypt2::IPCrypt2(pdns::ipcrypt2::IPCryptMethod::pfx, "12345678901234567890123456789012");

  auto encip = ipcrypt.encrypt(ComboAddress("127.0.0.1"));
  BOOST_CHECK(encip.isIPv4());
  BOOST_CHECK_NE(ComboAddress("127.0.0.1").toLogString(), encip.toLogString());

  encip = ipcrypt.encrypt(ComboAddress("::1"));
  BOOST_CHECK(encip.isIPv6());
  BOOST_CHECK_NE(ComboAddress("::1").toLogString(), encip.toLogString());
}

BOOST_AUTO_TEST_CASE(pfx_bad_key)
{
  BOOST_CHECK_THROW(
    auto ipcrypt = pdns::ipcrypt2::IPCrypt2(pdns::ipcrypt2::IPCryptMethod::pfx, "notlongenough"), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(pfx_preserves)
{
  auto ipcrypt = pdns::ipcrypt2::IPCrypt2(pdns::ipcrypt2::IPCryptMethod::pfx, "12345678901234567890123456789012");

  auto encip = ipcrypt.encrypt(ComboAddress("127.0.0.1"));
  BOOST_CHECK(encip.isIPv4());
  auto encip2 = ipcrypt.encrypt(ComboAddress("127.0.0.2"));
  BOOST_CHECK(encip2.isIPv4());

  BOOST_CHECK(encip != encip2);

  auto nw = Netmask(encip, 24);
  BOOST_CHECK(nw.match(encip));
  BOOST_CHECK(nw.match(encip2));
}

BOOST_AUTO_TEST_CASE(assignment)
{
  std::optional<pdns::ipcrypt2::IPCrypt2> optIPCrypt;
  optIPCrypt = std::make_optional(pdns::ipcrypt2::IPCrypt2(pdns::ipcrypt2::IPCryptMethod::pfx, "12345678901234567890123456789012"));

  BOOST_CHECK(optIPCrypt.has_value());

  auto encip = optIPCrypt->encrypt(ComboAddress("127.0.0.1"));
  BOOST_CHECK(encip.isIPv4());
  BOOST_CHECK_NE(ComboAddress("127.0.0.1").toLogString(), encip.toLogString());

  encip = optIPCrypt->encrypt(ComboAddress("::1"));
  BOOST_CHECK(encip.isIPv6());
  BOOST_CHECK_NE(ComboAddress("::1").toLogString(), encip.toLogString());
}

BOOST_AUTO_TEST_CASE(unsupported_method)
{
  BOOST_CHECK_THROW(
    auto ipcrypt = pdns::ipcrypt2::IPCrypt2(pdns::ipcrypt2::IPCryptMethod::deterministic, ""), std::runtime_error);
}

BOOST_AUTO_TEST_SUITE_END()

#endif // HAVE_IPCRYPT2
