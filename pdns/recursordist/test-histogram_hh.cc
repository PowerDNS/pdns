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

#include "histogram.hh"

BOOST_AUTO_TEST_SUITE(histogram_hh)

BOOST_AUTO_TEST_CASE(test_simple)
{
  auto h = pdns::AtomicHistogram("myname-", {1, 3, 5, 10, 100});

  h(0);
  h(1);
  h(1);
  h(3);
  h(4);
  h(100);
  h(101);
  h(-1); // actually a very large value, but for sum it will boil down to be -1 */

  auto data = h.getRawData();
  BOOST_CHECK_EQUAL(data.size(), 6U);
  uint64_t expected[] = {3, 1, 1, 0, 1, 2};
  size_t i = 0;
  for (auto e : expected) {
    BOOST_CHECK_EQUAL(data[i++].d_count, e);
  }

  auto c = h.getCumulativeCounts();
  BOOST_CHECK_EQUAL(data.size(), 6U);
  uint64_t cexpected[] = {3, 4, 5, 5, 6, 8};
  i = 0;
  for (auto e : cexpected) {
    BOOST_CHECK_EQUAL(c[i++], e);
  }
  BOOST_CHECK_EQUAL(h.getSum(), 209U);
}

BOOST_AUTO_TEST_SUITE_END()
