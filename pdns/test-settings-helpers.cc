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

#include "settings-helpers.hh"

BOOST_AUTO_TEST_SUITE(test_settings_helpers)

BOOST_AUTO_TEST_CASE(test_Basic)
{
  pdns::settings::helpers::SetOnlyOnce<bool> var;
  // accessing an unset value will throw
  BOOST_CHECK_THROW(var.get(), std::runtime_error);
  var.set(true);
  BOOST_CHECK_EQUAL(var.get(), true);
  BOOST_CHECK_THROW(var.set(false), std::runtime_error);
}

BOOST_AUTO_TEST_SUITE_END();
