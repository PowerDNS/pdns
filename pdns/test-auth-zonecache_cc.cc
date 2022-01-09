
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

#define BOOST_TEST_DYN_LINK
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

  vector<tuple<DNSName, int>> zone_indices{
    {DNSName("example.org."), 1},
  };
  cache.setReplacePending();
  cache.replace(zone_indices);

  int zoneId = 0;
  bool found = cache.getEntry(DNSName("example.org."), zoneId);
  if (!found || zoneId != 1) {
    BOOST_FAIL("zone added in replace() not found");
  }
}

BOOST_AUTO_TEST_CASE(test_add_while_pending_replace)
{
  AuthZoneCache cache;
  cache.setRefreshInterval(3600);

  vector<tuple<DNSName, int>> zone_indices{
    {DNSName("powerdns.org."), 1}};
  cache.setReplacePending();
  cache.add(DNSName("example.org."), 2);
  cache.replace(zone_indices);

  int zoneId = 0;
  bool found = cache.getEntry(DNSName("example.org."), zoneId);
  if (!found || zoneId != 2) {
    BOOST_FAIL("zone added while replace was pending not found");
  }
}

BOOST_AUTO_TEST_CASE(test_remove_while_pending_replace)
{
  AuthZoneCache cache;
  cache.setRefreshInterval(3600);

  vector<tuple<DNSName, int>> zone_indices{
    {DNSName("powerdns.org."), 1}};
  cache.setReplacePending();
  cache.remove(DNSName("powerdns.org."));
  cache.replace(zone_indices);

  int zoneId = 0;
  bool found = cache.getEntry(DNSName("example.org."), zoneId);
  if (found) {
    BOOST_FAIL("zone removed while replace was pending is found");
  }
}

// Add zone using .add(), but also in the .replace() data
BOOST_AUTO_TEST_CASE(test_add_while_pending_replace_duplicate)
{
  AuthZoneCache cache;
  cache.setRefreshInterval(3600);

  vector<tuple<DNSName, int>> zone_indices{
    {DNSName("powerdns.org."), 1},
    {DNSName("example.org."), 2},
  };
  cache.setReplacePending();
  cache.add(DNSName("example.org."), 3);
  cache.replace(zone_indices);

  int zoneId = 0;
  bool found = cache.getEntry(DNSName("example.org."), zoneId);
  if (!found || zoneId == 0) {
    BOOST_FAIL("zone added while replace was pending not found");
  }
  if (zoneId != 3) {
    BOOST_FAIL(string("zoneId got overwritten using replace() data (zoneId=") + std::to_string(zoneId) + ")");
  }
}

BOOST_AUTO_TEST_SUITE_END();
