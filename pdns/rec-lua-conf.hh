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
#include "sholder.hh"
#include "sortlist.hh"
#include "filterpo.hh"
#include "remote_logger.hh"
#include "validate.hh"

class LuaConfigItems 
{
public:
  LuaConfigItems();
  SortList sortlist;
  DNSFilterEngine dfe;
  map<DNSName,dsmap_t> dsAnchors;
  map<DNSName,std::string> negAnchors;
  std::shared_ptr<RemoteLogger> protobufServer{nullptr};
  std::shared_ptr<RemoteLogger> outgoingProtobufServer{nullptr};
  uint8_t protobufMaskV4{32};
  uint8_t protobufMaskV6{128};
  bool protobufTaggedOnly{false};
  bool protobufResponsesOnly{false};
};

extern GlobalStateHolder<LuaConfigItems> g_luaconfs;

struct luaConfigDelayedThreads
{
  std::vector<std::tuple<ComboAddress, boost::optional<DNSFilterEngine::Policy>, uint32_t, size_t, TSIGTriplet, size_t, ComboAddress, uint16_t> > rpzMasterThreads;
};

void loadRecursorLuaConfig(const std::string& fname, luaConfigDelayedThreads& delayedThreads);
void startLuaConfigDelayedThreads(const luaConfigDelayedThreads& delayedThreads);

