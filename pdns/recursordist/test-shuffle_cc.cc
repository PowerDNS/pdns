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
#include <boost/test/unit_test.hpp>

#include "shuffle.hh"
#include "test-common.hh"

BOOST_AUTO_TEST_SUITE(shuffle_cc)

BOOST_AUTO_TEST_CASE(test_simple)
{
  std::vector<DNSRecord> list;
  auto* address = &list;
  addRecordToList(list, DNSName("foo"), QType::A, "1.2.3.4");
  addRecordToList(list, DNSName("foo2"), QType::A, "1.2.3.4");
  auto dups = pdns::dedupRecords(list);
  BOOST_CHECK_EQUAL(dups, 0U);
  BOOST_CHECK_EQUAL(list.size(), 2U);
  addRecordToList(list, DNSName("foo"), QType::A, "1.2.3.4");
  dups = pdns::dedupRecords(list);
  BOOST_CHECK_EQUAL(dups, 1U);
  BOOST_CHECK_EQUAL(list.size(), 2U);
  addRecordToList(list, DNSName("Foo"), QType::A, "1.2.3.4");
  addRecordToList(list, DNSName("FoO"), QType::A, "1.2.3.4", DNSResourceRecord::ADDITIONAL, 999);
  dups = pdns::dedupRecords(list);
  BOOST_CHECK_EQUAL(dups, 2U);
  BOOST_CHECK_EQUAL(list.size(), 2U);
  BOOST_CHECK_EQUAL(address, &list);
}

BOOST_AUTO_TEST_SUITE_END()
