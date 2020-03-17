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

#include <iputils.hh>

struct ProxyProtocolValue
{
  std::string content;
  uint8_t type;
};

static const size_t s_proxyProtocolMinimumHeaderSize = 16;

std::string makeLocalProxyHeader();
std::string makeProxyHeader(bool tcp, const ComboAddress& source, const ComboAddress& destination, const std::vector<ProxyProtocolValue>& values);

/* returns: number of bytes consumed (positive) after successful parse
         or number of bytes missing (negative)
         or unfixable parse error (0)*/
ssize_t isProxyHeaderComplete(const std::string& header, bool* proxy=nullptr, bool* tcp=nullptr, size_t* addrSizeOut=nullptr, uint8_t* protocolOut=nullptr);

/* returns: number of bytes consumed (positive) after successful parse
         or number of bytes missing (negative)
         or unfixable parse error (0)*/
ssize_t parseProxyHeader(const std::string& payload, bool& proxy, ComboAddress& source, ComboAddress& destination, bool& tcp, std::vector<ProxyProtocolValue>& values);
