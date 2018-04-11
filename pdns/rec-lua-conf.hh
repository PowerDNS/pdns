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
#include "validate.hh"

struct ProtobufExportConfig
{
  ComboAddress server;
  uint64_t maxQueuedEntries{100};
  uint16_t timeout{2};
  uint16_t reconnectWaitTime{1};
  bool asyncConnect{false};
  bool enabled{false};
};

class LuaConfigItems 
{
public:
  LuaConfigItems();
  SortList sortlist;
  DNSFilterEngine dfe;
  map<DNSName,dsmap_t> dsAnchors;
  map<DNSName,std::string> negAnchors;
  /* we need to increment this every time the configuration
     is reloaded, so we know if we need to reload the protobuf
     remote loggers */
  ProtobufExportConfig protobufExportConfig;
  ProtobufExportConfig outgoingProtobufExportConfig;
  uint64_t generation{0};
  uint8_t protobufMaskV4{32};
  uint8_t protobufMaskV6{128};
  bool protobufTaggedOnly{false};
};

extern GlobalStateHolder<LuaConfigItems> g_luaconfs;
void loadRecursorLuaConfig(const std::string& fname, bool checkOnly);

