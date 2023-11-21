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
#include "dnsdist-internal-queries.hh"
#include "dnsdist-nghttp2-in.hh"
#include "dnsdist-tcp.hh"
#include "doh.hh"
#include "doq.hh"

std::unique_ptr<CrossProtocolQuery> getUDPCrossProtocolQueryFromDQ(DNSQuestion& dq);

namespace dnsdist
{
std::unique_ptr<CrossProtocolQuery> getInternalQueryFromDQ(DNSQuestion& dq, bool isResponse)
{
  auto protocol = dq.getProtocol();
  if (protocol == dnsdist::Protocol::DoUDP || protocol == dnsdist::Protocol::DNSCryptUDP) {
    return getUDPCrossProtocolQueryFromDQ(dq);
  }
#ifdef HAVE_DNS_OVER_HTTPS
  else if (protocol == dnsdist::Protocol::DoH) {
#ifdef HAVE_LIBH2OEVLOOP
    if (dq.ids.cs->dohFrontend->d_library == "h2o") {
      return getDoHCrossProtocolQueryFromDQ(dq, isResponse);
    }
#endif /* HAVE_LIBH2OEVLOOP */
    return getTCPCrossProtocolQueryFromDQ(dq);
  }
#endif
#ifdef HAVE_DNS_OVER_QUIC
  else if (protocol == dnsdist::Protocol::DoQ) {
    return getDOQCrossProtocolQueryFromDQ(dq, isResponse);
  }
#endif
#ifdef HAVE_DNS_OVER_HTTP3
  else if (protocol == dnsdist::Protocol::DoH3) {
    return getDOH3CrossProtocolQueryFromDQ(dq, isResponse);
  }
#endif
  else {
    return getTCPCrossProtocolQueryFromDQ(dq);
  }
}
}
