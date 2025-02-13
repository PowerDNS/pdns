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

#include <cstddef>
#include <cstdint>
#include <string>

#include "config.h"

#include "dnsname.hh"
#include "iputils.hh"

#ifndef DISABLE_PROTOBUF

class DnstapMessage
{
public:
  enum class MessageType : uint32_t
  {
    auth_query = 1,
    auth_response = 2,
    resolver_query = 3,
    resolver_response = 4,
    client_query = 5,
    client_response = 6,
    forwarder_query = 7,
    forwarded_response = 8,
    stub_query = 9,
    stub_response = 10,
    tool_query = 11,
    tool_response = 12
  };
  enum class ProtocolType : uint32_t
  {
    DoUDP = 1,
    DoTCP = 2,
    DoT = 3,
    DoH = 4,
    DNSCryptUDP = 5,
    DNSCryptTCP = 6,
    DoQ = 7
  };
  enum class HttpProtocolType : uint32_t
  {
    HTTP1 = 1,
    HTTP2 = 2,
    HTTP3 = 3,
  };

  DnstapMessage(std::string&& buffer, MessageType type, const std::string& identity, const ComboAddress* requestor, const ComboAddress* responder, ProtocolType protocol, const char* packet, size_t len, const struct timespec* queryTime, const struct timespec* responseTime, const boost::optional<const DNSName&>& auth = boost::none, const boost::optional<HttpProtocolType> httpProtocol = boost::none);

  void setExtra(const std::string& extra);
  std::string&& getBuffer();

private:
  std::string d_buffer;
};

#endif /* DISABLE_PROTOBUF */
