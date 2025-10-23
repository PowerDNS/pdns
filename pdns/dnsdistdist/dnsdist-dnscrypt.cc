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
#include "dnsdist-dnscrypt.hh"

#ifdef HAVE_DNSCRYPT
#include "dolog.hh"
#include "dnsdist.hh"
#include "dnsdist-metrics.hh"
#include "dnscrypt.hh"

bool handleDNSCryptQuery(PacketBuffer& packet, DNSCryptQuery& query, bool tcp, time_t now, PacketBuffer& response)
{
  query.parsePacket(packet, tcp, now);

  if (!query.isValid()) {
    vinfolog("Dropping DNSCrypt invalid query");
    return false;
  }

  if (!query.isEncrypted()) {
    query.getCertificateResponse(now, response);

    return false;
  }

  if (packet.size() < static_cast<uint16_t>(sizeof(struct dnsheader))) {
    ++dnsdist::metrics::g_stats.nonCompliantQueries;
    return false;
  }

  return true;
}

bool encryptResponse(PacketBuffer& response, size_t maximumSize, bool tcp, std::unique_ptr<DNSCryptQuery>& dnsCryptQuery)
{
  if (dnsCryptQuery) {
    int res = dnsCryptQuery->encryptResponse(response, maximumSize, tcp);
    if (res != 0) {
      /* dropping response */
      vinfolog("Error encrypting the response, dropping.");
      return false;
    }
  }
  return true;
}
#endif

bool checkDNSCryptQuery([[maybe_unused]] const ClientState& clientState, [[maybe_unused]] PacketBuffer& query, [[maybe_unused]] std::unique_ptr<DNSCryptQuery>& dnsCryptQuery, [[maybe_unused]] time_t now, [[maybe_unused]] bool tcp)
{
#ifdef HAVE_DNSCRYPT
  if (clientState.dnscryptCtx) {
    PacketBuffer response;
    dnsCryptQuery = std::make_unique<DNSCryptQuery>(clientState.dnscryptCtx);

    bool decrypted = handleDNSCryptQuery(query, *dnsCryptQuery, tcp, now, response);

    if (!decrypted) {
      if (!response.empty()) {
        query = std::move(response);
        return true;
      }
      throw std::runtime_error("Unable to decrypt DNSCrypt query, dropping.");
    }
  }
#endif /* HAVE_DNSCRYPT */
  return false;
}
