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
#ifndef COMMON_STARTUP_HH
#define COMMON_STARTUP_HH

#include "auth-packetcache.hh"
#include "auth-querycache.hh"
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

extern ArgvMap theArg;
extern StatBag S;  //!< Statistics are gathered across PDNS via the StatBag class S
extern AuthPacketCache PC; //!< This is the main PacketCache, shared across all threads
extern AuthQueryCache QC;
extern std::unique_ptr<DNSProxy> DP;
extern std::unique_ptr<DynListener> dl;
extern CommunicatorClass Communicator;
extern std::shared_ptr<UDPNameserver> N;
extern vector<std::shared_ptr<UDPNameserver> > g_udpReceivers;
extern int avg_latency;
extern std::unique_ptr<TCPNameserver> TN;
extern ArgvMap & arg( void );
extern void declareArguments();
extern void declareStats();
extern void mainthread();
extern int isGuarded( char ** );
void carbonDumpThread();
extern bool g_anyToTcp;
extern bool g_8bitDNS;
#ifdef HAVE_LUA_RECORDS
extern bool g_doLuaRecord;
extern bool g_LuaRecordSharedState;
#endif // HAVE_LUA_RECORDS

#endif // COMMON_STARTUP_HH
