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
#include <string>

#include "config.h"

#include "dnsname.hh"
#include "iputils.hh"
#include "protozero.hh"

class DnstapMessage
{
public:
  DnstapMessage(std::string& buffer, int32_t type, const std::string& identity, const ComboAddress* requestor, const ComboAddress* responder, bool isTCP, const char* packet, const size_t len, const struct timespec* queryTime, const struct timespec* responseTime, boost::optional<const DNSName&> auth=boost::none);

  void setExtra(const std::string& extra);

protected:
  std::string& d_buffer;
};
