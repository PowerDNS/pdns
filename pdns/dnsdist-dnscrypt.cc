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
#include "dolog.hh"
#include "dnsdist.hh"
#include "dnscrypt.hh"

#ifdef HAVE_DNSCRYPT
int handleDnsCryptQuery(DnsCryptContext* ctx, char* packet, uint16_t len, std::shared_ptr<DnsCryptQuery>& query, uint16_t* decryptedQueryLen, bool tcp, std::vector<uint8_t>& response)
{
  query->ctx = ctx;

  ctx->parsePacket(packet, len, query, tcp, decryptedQueryLen);

  if (query->valid == false) {
    vinfolog("Dropping DNSCrypt invalid query");
    return false;
  }

  if (query->encrypted == false) {
    ctx->getCertificateResponse(query, response);

    return false;
  }

  if(*decryptedQueryLen < (int)sizeof(struct dnsheader)) {
    g_stats.nonCompliantQueries++;
    return false;
  }

  return true;
}
#endif
