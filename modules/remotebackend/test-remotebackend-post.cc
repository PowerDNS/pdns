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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "pdns/namespaces.hh"
#include "pdns/dns.hh"
#include "pdns/dnsbackend.hh"
#include "pdns/dnspacket.hh"
#include "pdns/pdnsexception.hh"
#include "pdns/logger.hh"
#include "pdns/arguments.hh"
#include "pdns/json.hh"
#include "pdns/statbag.hh"
#include "pdns/auth-packetcache.hh"
#include "pdns/auth-querycache.hh"

StatBag S;
AuthPacketCache PC;
AuthQueryCache QC;
ArgvMap& arg()
{
  static ArgvMap arg;
  return arg;
};

class RemoteLoader
{
public:
  RemoteLoader();
};

DNSBackend* be;

#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MAIN
#define BOOST_TEST_MODULE unit

#include <boost/test/unit_test.hpp>
#include <boost/assign/list_of.hpp>

#include <boost/tuple/tuple.hpp>

struct RemotebackendSetup
{
  RemotebackendSetup()
  {
    be = 0;
    try {
      // setup minimum arguments
      ::arg().set("module-dir") = "./.libs";
      new RemoteLoader();
      BackendMakers().launch("remote");
      // then get us a instance of it
      ::arg().set("remote-connection-string") = "http:url=http://localhost:62434/dns,post=1";
      ::arg().set("remote-dnssec") = "yes";
      be = BackendMakers().all()[0];
    }
    catch (PDNSException& ex) {
      BOOST_TEST_MESSAGE("Cannot start remotebackend: " << ex.reason);
    };
  }
  ~RemotebackendSetup() {}
};

BOOST_GLOBAL_FIXTURE(RemotebackendSetup);
