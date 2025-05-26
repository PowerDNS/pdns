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
#include "auth-packetcache.hh"
#include "auth-querycache.hh"
#include "auth-zonecache.hh"
#include "utility.hh"
#include "arguments.hh"
#include "communicator.hh"
#include "distributor.hh"
#include "dnspacket.hh"
#include "dnsproxy.hh"
#include "dynlistener.hh"
#include "nameserver.hh"
#include "statbag.hh"
#include "tcpreceiver.hh"
#include "dnsseckeeper.hh"

extern time_t g_starttime;
extern ArgvMap theArg;
extern StatBag S; //!< Statistics are gathered across PDNS via the StatBag class S
extern AuthPacketCache PC; //!< This is the main PacketCache, shared across all threads
extern AuthQueryCache QC;
extern std::unique_ptr<DNSProxy> DP;
extern CommunicatorClass Communicator;
void carbonDumpThread(); // Implemented in auth-carbon.cc. Avoids having an auth-carbon.hh declaring exactly one function.
extern bool g_anyToTcp;
extern bool g_8bitDNS;
extern NetmaskGroup g_proxyProtocolACL;
extern size_t g_proxyProtocolMaximumSize;
#ifdef HAVE_LUA_RECORDS
extern bool g_doLuaRecord;
extern bool g_LuaRecordSharedState;
extern bool g_luaRecordInsertWhitespace;
extern time_t g_luaHealthChecksInterval;
extern time_t g_luaHealthChecksExpireDelay;
extern time_t g_luaConsistentHashesExpireDelay;
extern time_t g_luaConsistentHashesCleanupInterval;
#endif // HAVE_LUA_RECORDS
extern bool g_views;
