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

#include "dnsdist.hh"
#include "mplexer.hh"
#include "sstuff.hh"

struct HealthCheckData
{
  HealthCheckData(std::shared_ptr<FDMultiplexer>& mplexer, const std::shared_ptr<DownstreamState>& ds, Socket&& sock, DNSName&& checkName, uint16_t checkType, uint16_t checkClass, uint16_t queryID): d_mplexer(mplexer), d_ds(ds), d_sock(std::move(sock)), d_checkName(std::move(checkName)), d_checkType(checkType), d_checkClass(checkClass), d_queryID(queryID)
  {
  }

  std::shared_ptr<FDMultiplexer> d_mplexer;
  const std::shared_ptr<DownstreamState> d_ds;
  Socket d_sock;
  DNSName d_checkName;
  uint16_t d_checkType;
  uint16_t d_checkClass;
  uint16_t d_queryID;
};

extern bool g_verboseHealthChecks;

void updateHealthCheckResult(const std::shared_ptr<DownstreamState>& dss, bool newState);
bool queueHealthCheck(std::shared_ptr<FDMultiplexer>& mplexer, const std::shared_ptr<DownstreamState>& ds, bool initial=false);
void handleQueuedHealthChecks(std::shared_ptr<FDMultiplexer>& mplexer, bool initial=false);

