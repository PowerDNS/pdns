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

#include "iputils.hh"

namespace dnsdist
{
class IncomingConcurrentTCPConnectionsManager
{
public:
  enum class NewConnectionResult : uint8_t
  {
    Allowed = 0,
    Denied = 1,
    Restricted = 2,
  };
  static NewConnectionResult accountNewTCPConnection(const ComboAddress& from, bool isTLS);
  static bool isClientOverThreshold(const ComboAddress& from);
  static void accountTLSNewSession(const ComboAddress& from);
  static void accountTLSResumedSession(const ComboAddress& from);
  static void accountClosedTCPConnection(const ComboAddress& from);
  static void banClientFor(const ComboAddress& from, time_t now, uint32_t seconds);
  static void cleanup(time_t now);
};
}
