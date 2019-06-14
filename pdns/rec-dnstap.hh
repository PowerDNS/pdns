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
#pragma once

#ifdef HAVE_FSTRM
#include "dnstap.hh"
#endif /* HAVE_FSTRM */

class RecDnstapMessage : public DnstapMessage
{
public:
  RecDnstapMessage(const std::string& identity, const ComboAddress* requestor, const ComboAddress* responder, bool isTCP, boost::optional<const DNSName&> auth, const char* packet, const size_t len, const struct timespec* queryTime, const struct timespec* responseTime)
      : DnstapMessage(identity, requestor, responder, isTCP, packet, len, queryTime, responseTime) {
    const struct dnsheader* dh = reinterpret_cast<const struct dnsheader*>(packet);
    dnstap::Message* message = proto_message.mutable_message();
    message->set_type(!dh->qr ? dnstap::Message_Type_RESOLVER_QUERY : dnstap::Message_Type_RESOLVER_RESPONSE);
    if (auth) {
      message->set_query_zone(auth->toDNSString());
    }
  }
};
