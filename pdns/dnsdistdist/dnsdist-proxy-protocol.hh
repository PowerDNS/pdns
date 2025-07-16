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

#include <string>

#include "iputils.hh"
#include "noinitvector.hh"
#include "proxy-protocol.hh"

struct DNSQuestion;

std::string getProxyProtocolPayload(const DNSQuestion& dq);

bool addProxyProtocol(DNSQuestion& dnsQuestion, size_t* proxyProtocolPayloadSize = nullptr);
bool addProxyProtocol(DNSQuestion& dq, const std::string& payload);
bool addProxyProtocol(PacketBuffer& buffer, const std::string& payload);
bool addProxyProtocol(PacketBuffer& buffer, bool tcp, const ComboAddress& source, const ComboAddress& destination, const std::vector<ProxyProtocolValue>& values);

bool expectProxyProtocolFrom(const ComboAddress& remote);
bool handleProxyProtocol(const ComboAddress& remote, bool isTCP, const NetmaskGroup& acl, PacketBuffer& query, ComboAddress& realRemote, ComboAddress& realDestination, std::vector<ProxyProtocolValue>& values);
