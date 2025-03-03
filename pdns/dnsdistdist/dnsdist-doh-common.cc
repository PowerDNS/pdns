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
#include "base64.hh"
#include "dnsdist-doh-common.hh"
#include "dnsdist.hh"

#ifdef HAVE_DNS_OVER_HTTPS
void DOHFrontend::rotateTicketsKey(time_t now)
{
  return d_tlsContext->rotateTicketsKey(now);
}

void DOHFrontend::loadTicketsKeys(const std::string& keyFile)
{
  return d_tlsContext->loadTicketsKeys(keyFile);
}

void DOHFrontend::loadTicketsKey(const std::string& key)
{
  return d_tlsContext->loadTicketsKey(key);
}

void DOHFrontend::handleTicketsKeyRotation()
{
}

std::string DOHFrontend::getNextTicketsKeyRotation() const
{
  return d_tlsContext->getNextTicketsKeyRotation();
}

size_t DOHFrontend::getTicketsKeysCount()
{
  return d_tlsContext->getTicketsKeysCount();
}

void DOHFrontend::reloadCertificates()
{
  if (isHTTPS()) {
    d_tlsContext->setupTLS();
  }
}

void DOHFrontend::setup()
{
  if (isHTTPS()) {
    if (!d_tlsContext->setupTLS()) {
      throw std::runtime_error("Error setting up TLS context for DoH listener on '" + d_tlsContext->d_addr.toStringWithPort());
    }
  }
}

#endif /* HAVE_DNS_OVER_HTTPS */

namespace dnsdist::doh
{
std::optional<PacketBuffer> getPayloadFromPath(const std::string_view& path)
{
  std::optional<PacketBuffer> result{std::nullopt};

  if (path.size() <= 5) {
    return result;
  }

  auto pos = path.find("?dns=");
  if (pos == string::npos) {
    pos = path.find("&dns=");
  }

  if (pos == string::npos) {
    return result;
  }

  // need to base64url decode this
  string sdns;
  const size_t payloadSize = path.size() - pos - 5;
  size_t neededPadding = 0;
  switch (payloadSize % 4) {
  case 2:
    neededPadding = 2;
    break;
  case 3:
    neededPadding = 1;
    break;
  }
  sdns.reserve(payloadSize + neededPadding);
  sdns = path.substr(pos + 5);
  for (auto& entry : sdns) {
    switch (entry) {
    case '-':
      entry = '+';
      break;
    case '_':
      entry = '/';
      break;
    }
  }

  if (neededPadding != 0) {
    // re-add padding that may have been missing
    sdns.append(neededPadding, '=');
  }

  PacketBuffer decoded;
  /* rough estimate so we hopefully don't need a new allocation later */
  /* We reserve at few additional bytes to be able to add EDNS later */
  const size_t estimate = ((sdns.size() * 3) / 4);
  decoded.reserve(estimate);
  if (B64Decode(sdns, decoded) < 0) {
    return result;
  }

  result = std::move(decoded);
  return result;
}
}
