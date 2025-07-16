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

#include "dnsdist-frontend.hh"
#include "dnsdist.hh"
#include "dnsdist-configuration.hh"

namespace dnsdist
{

const std::vector<std::shared_ptr<ClientState>>& getFrontends()
{
  return dnsdist::configuration::getImmutableConfiguration().d_frontends;
}

std::vector<std::shared_ptr<DNSCryptContext>> getDNSCryptFrontends(bool udpOnly)
{
  std::vector<std::shared_ptr<DNSCryptContext>> results;
  for (const auto& frontend : getFrontends()) {
    if (frontend->getProtocol() == dnsdist::Protocol::DNSCryptUDP || (!udpOnly && frontend->getProtocol() == dnsdist::Protocol::DNSCryptTCP)) {
      results.push_back(frontend->dnscryptCtx);
    }
  }
  return results;
}

std::vector<std::shared_ptr<TLSFrontend>> getDoTFrontends()
{
  std::vector<std::shared_ptr<TLSFrontend>> results;
  for (const auto& frontend : getFrontends()) {
    if (frontend->getProtocol() == dnsdist::Protocol::DoT) {
      results.push_back(frontend->tlsFrontend);
    }
  }
  return results;
}

std::vector<std::shared_ptr<DOHFrontend>> getDoHFrontends()
{
  std::vector<std::shared_ptr<DOHFrontend>> results;
  for (const auto& frontend : getFrontends()) {
    if (frontend->getProtocol() == dnsdist::Protocol::DoH) {
      results.push_back(frontend->dohFrontend);
    }
  }
  return results;
}

std::vector<std::shared_ptr<DOQFrontend>> getDoQFrontends()
{
  std::vector<std::shared_ptr<DOQFrontend>> results;
  for (const auto& frontend : getFrontends()) {
    if (frontend->getProtocol() == dnsdist::Protocol::DoQ) {
      results.push_back(frontend->doqFrontend);
    }
  }
  return results;
}

std::vector<std::shared_ptr<DOH3Frontend>> getDoH3Frontends()
{
  std::vector<std::shared_ptr<DOH3Frontend>> results;
  for (const auto& frontend : getFrontends()) {
    if (frontend->getProtocol() == dnsdist::Protocol::DoH3) {
      results.push_back(frontend->doh3Frontend);
    }
  }
  return results;
}
}
