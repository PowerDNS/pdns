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
#include "dnsname.hh"
#define CATCH_CONFIG_NO_MAIN
#include <catch2/catch_test_macros.hpp>
#include <catch2/benchmark/catch_benchmark.hpp>

#include "dnsdist.hh"
#include "dnsdist-idstate.hh"
#include "dnsdist-dnsparser.hh"
#include "dnsdist-actions-factory.hh"

TEST_CASE("Actions/RCodeAction", "[actions]") {
  InternalQueryState ids;
  PacketBuffer data;
  GenericDNSPacketWriter<PacketBuffer> pwQ(data, DNSName("dnsdist.test.powerdns.com"), QType::A, QClass::IN, 0);
  pwQ.getHeader()->rd = 1;

  dnsdist::ResponseConfig rconfig;
  auto action = dnsdist::actions::getRCodeAction(RCode::NXDomain, rconfig);

  DNSQuestion dq(ids, data); // NOLINT
  std::string ruleresult;
  BENCHMARK("set-nxd") {
    return (*action)(&dq, &ruleresult);
  };

  rconfig.setAA = true;
  action = dnsdist::actions::getRCodeAction(RCode::NXDomain, rconfig);
  BENCHMARK("set-nxd-and-AA") {
    return (*action)(&dq, &ruleresult);
  };
}
