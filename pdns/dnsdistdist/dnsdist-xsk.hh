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

#include "config.h"

#ifdef HAVE_XSK
class XskPacket;
class XskSocket;
class XskWorker;

#include <memory>

namespace dnsdist::xsk
{
void XskResponderThread(std::shared_ptr<DownstreamState> dss, std::shared_ptr<XskWorker> xskInfo);
bool XskIsQueryAcceptable(const XskPacket& packet, ClientState& clientState, bool& expectProxyProtocol);
bool XskProcessQuery(ClientState& clientState, XskPacket& packet);
void XskRouter(std::shared_ptr<XskSocket> xsk);
void XskClientThread(ClientState* clientState);
void addDestinationAddress(const ComboAddress& addr);
void removeDestinationAddress(const ComboAddress& addr);
void clearDestinationAddresses();

extern std::vector<std::shared_ptr<XskSocket>> g_xsk;
}
#endif /* HAVE_XSK */
