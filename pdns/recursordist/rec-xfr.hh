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

#include <string>
#include <thread>

#include "iputils.hh"

class DNSName;
class SOARecordContent;

// Please make sure that the struct below only contains value types since they are used as parameters in a thread ct
struct ZoneXFRParams
{
  std::string name;
  std::vector<ComboAddress> primaries;
  ComboAddress localAddress;
  std::shared_ptr<const SOARecordContent> soaRecordContent;
  TSIGTriplet tsigtriplet;
  size_t maxReceivedMBytes{0};
  size_t zoneSizeHint{0};
  uint16_t xfrTimeout{20};
};

// A struct that holds the condition var and related stuff to allow notifies to be sent to the tread owning
// the struct.
struct ZoneWaiter
{
  ZoneWaiter(std::thread::id arg) :
    id(arg) {}
  std::thread::id id;
  std::mutex mutex;
  std::condition_variable condVar;
  std::atomic<bool> stop{false};
};

bool notifyZoneTracker(const DNSName& name);
void insertZoneTracker(const DNSName& zoneName, ZoneWaiter& waiter);
void clearZoneTracker(const DNSName& zoneName);
