/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2021  PowerDNS.COM BV

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

#ifndef BOOST_TEST_DYN_LINK
#define BOOST_TEST_DYN_LINK
#endif

#define BOOST_TEST_NO_MAIN

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <boost/test/unit_test.hpp>

#include "auth-zonecache.hh"
#include "misc.hh"

BOOST_AUTO_TEST_SUITE(test_auth_zonecache_cc)

BOOST_AUTO_TEST_CASE(test_replace)
{
  AuthZoneCache cache;
  cache.setRefreshInterval(3600);

  vector<std::tuple<ZoneName, domainid_t>> zone_indices{
    {ZoneName("example.org."), 1},
  };
  cache.setReplacePending();
  cache.replace(zone_indices);

  domainid_t zoneId = 0;
  ZoneName zone("example.org");
  bool found = cache.getEntry(zone, zoneId);
  if (!found || zoneId != 1) {
    BOOST_FAIL("zone added in replace() not found");
  }
}

BOOST_AUTO_TEST_CASE(test_add_while_pending_replace)
{
  AuthZoneCache cache;
  cache.setRefreshInterval(3600);

  vector<std::tuple<ZoneName, domainid_t>> zone_indices{
    {ZoneName("powerdns.org."), 1}};
  cache.setReplacePending();
  cache.add(ZoneName("example.org."), 2);
  cache.replace(zone_indices);

  domainid_t zoneId = 0;
  ZoneName zone("example.org");
  bool found = cache.getEntry(zone, zoneId);
  if (!found || zoneId != 2) {
    BOOST_FAIL("zone added while replace was pending not found");
  }
}

BOOST_AUTO_TEST_CASE(test_remove_while_pending_replace)
{
  AuthZoneCache cache;
  cache.setRefreshInterval(3600);

  vector<std::tuple<ZoneName, domainid_t>> zone_indices{
    {ZoneName("powerdns.org."), 1}};
  cache.setReplacePending();
  cache.remove(ZoneName("powerdns.org."));
  cache.replace(zone_indices);

  domainid_t zoneId = 0;
  ZoneName zone("example.org");
  bool found = cache.getEntry(zone, zoneId);
  if (found) {
    BOOST_FAIL("zone removed while replace was pending is found");
  }
}

// Add zone using .add(), but also in the .replace() data
BOOST_AUTO_TEST_CASE(test_add_while_pending_replace_duplicate)
{
  AuthZoneCache cache;
  cache.setRefreshInterval(3600);

  vector<std::tuple<ZoneName, domainid_t>> zone_indices{
    {ZoneName("powerdns.org."), 1},
    {ZoneName("example.org."), 2},
  };
  cache.setReplacePending();
  cache.add(ZoneName("example.org."), 3);
  cache.replace(zone_indices);

  domainid_t zoneId = 0;
  ZoneName zone("example.org");
  bool found = cache.getEntry(zone, zoneId);
  if (!found || zoneId == 0) {
    BOOST_FAIL("zone added while replace was pending not found");
  }
  if (zoneId != 3) {
    BOOST_FAIL(string("zoneId got overwritten using replace() data (zoneId=") + std::to_string(zoneId) + ")");
  }
}

BOOST_AUTO_TEST_CASE(test_netmask)
{
  AuthZoneCache cache;
  cache.setRefreshInterval(3600);

  // Declare a few zones
  ZoneName bl("bug.less"); // NOLINT(readability-identifier-length)
  ZoneName bli("bug.less..inner");
  ZoneName blo("bug.less..outer");
  ZoneName fb("fewer.bugs"); // NOLINT(readability-identifier-length)
  ZoneName bp("bad.puns"); // NOLINT(readability-identifier-length)
  ZoneName nonexistent("non.existent");
  cache.add(bli, 42);
  cache.add(blo, 43);
  cache.add(fb, 100);
  cache.add(bp, 1000);

  // Declare a few networks
  std::string inner{"inner"};
  std::string outer{"outer"};
  std::string disjoint{"disjoint"};
  Netmask innerMask("20.25.4.0/24");
  Netmask outerMask("20.25.0.0/16");
  cache.updateNetwork(outerMask, outer);
  cache.updateNetwork(innerMask, inner);

  // Declare a few views
  cache.addToView(inner, bli);
  cache.addToView(outer, blo);

  domainid_t zoneId{0};
  std::string variant;
  std::string view;
  ZoneName search{};

  // Query from no known address
  bool found = cache.getEntry(bl, zoneId);
  if (found) {
    BOOST_FAIL("bug.less lookup should have failed");
  }

  // Query from inner zone
  Netmask nm(makeComboAddress("20.25.4.24")); // NOLINT(readability-identifier-length)
  view = cache.getViewFromNetwork(&nm);
  BOOST_CHECK_EQUAL(view, inner);
  variant = cache.getVariantFromView(bl, view);
  if (nm != innerMask) {
    BOOST_FAIL("bug.less lookup from inner zone reported wrong network " + nm.toString());
  }
  found = cache.getEntry(ZoneName(bl.operator const DNSName&(), variant), zoneId);
  if (!found) {
    BOOST_FAIL("bug.less lookup from inner zone should have succeeded");
  }
  if (zoneId != 42) {
    BOOST_FAIL("bug.less lookup from inner zone reported wrong id " + std::to_string(zoneId));
  }
  variant = cache.getVariantFromView(fb, view);
  BOOST_CHECK(variant.empty());
  if (nm != innerMask) {
    BOOST_FAIL("fewer.bugs lookup from inner zone reported wrong network " + nm.toString());
  }
  found = cache.getEntry(fb, zoneId);
  if (!found) {
    BOOST_FAIL("fewer.bugs lookup from inner zone should have succeeded");
  }
  if (zoneId != 100) {
    BOOST_FAIL("fewer.bugs lookup from inner zone reported wrong id " + std::to_string(zoneId));
  }

  // Query from outer zone
  nm = makeComboAddress("20.25.20.25");
  view = cache.getViewFromNetwork(&nm);
  BOOST_CHECK_EQUAL(view, outer);
  variant = cache.getVariantFromView(bl, view);
  if (nm != outerMask) {
    BOOST_FAIL("bug.less lookup from outer zone reported wrong network " + nm.toString());
  }
  found = cache.getEntry(ZoneName(bl.operator const DNSName&(), variant), zoneId);
  if (!found) {
    BOOST_FAIL("bug.less lookup from outer zone should have succeeded");
  }
  if (zoneId != 43) {
    BOOST_FAIL("bug.less lookup from outer zone reported wrong id " + std::to_string(zoneId));
  }
  variant = cache.getVariantFromView(bp, view);
  BOOST_CHECK(variant.empty());
  if (nm != outerMask) {
    BOOST_FAIL("bad.puns lookup from outer zone reported wrong network " + nm.toString());
  }
  found = cache.getEntry(bp, zoneId);
  if (!found) {
    BOOST_FAIL("bad.puns lookup from outer zone should have succeeded");
  }
  if (zoneId != 1000) {
    BOOST_FAIL("bad.puns lookup from outer zone reported wrong id " + std::to_string(zoneId));
  }

  // Query from no particular zone, should clear netmask
  nm = makeComboAddress("1.2.3.4");
  view = cache.getViewFromNetwork(&nm);
  BOOST_CHECK_EQUAL(view, "");
  variant = cache.getVariantFromView(nonexistent, view);
  BOOST_CHECK(variant.empty());
  found = cache.getEntry(nonexistent, zoneId);
  if (found) {
    BOOST_FAIL("non.existent lookup from the internet should have failed");
  }
  view = cache.getViewFromNetwork(&nm);
  BOOST_CHECK_EQUAL(view, "");
  variant = cache.getVariantFromView(bl, view);
  BOOST_CHECK(variant.empty());
  found = cache.getEntry(bl, zoneId);
  if (found) {
    BOOST_FAIL("bug.less lookup from the internet should have failed");
  }
  view = cache.getViewFromNetwork(&nm);
  BOOST_CHECK_EQUAL(view, "");
  variant = cache.getVariantFromView(bp, view);
  BOOST_CHECK(variant.empty());
  found = cache.getEntry(bp, zoneId);
  if (!found) {
    BOOST_FAIL("bad.puns lookup from the internet should have succeeded");
  }
  if (zoneId != 1000) {
    BOOST_FAIL("bad.puns lookup from the internet reported wrong id " + std::to_string(zoneId));
  }
}

BOOST_AUTO_TEST_SUITE_END();
