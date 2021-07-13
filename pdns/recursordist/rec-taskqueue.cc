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
#include "rec-taskqueue.hh"
#include "taskqueue.hh"
#include "syncres.hh"

static thread_local pdns::TaskQueue t_taskQueue;

void runTaskOnce(bool logErrors)
{
  t_taskQueue.runOnce(logErrors);
}

void pushTask(const DNSName& qname, uint16_t qtype, time_t deadline)
{
  t_taskQueue.push({qname, qtype, deadline, true});
}

uint64_t getTaskPushes()
{
  return broadcastAccFunction<uint64_t>([] { return t_taskQueue.getPushes(); });
}

uint64_t getTaskExpired()
{
  return broadcastAccFunction<uint64_t>([] { return t_taskQueue.getExpired(); });
}

uint64_t getTaskSize()
{
  return broadcastAccFunction<uint64_t>([] { return t_taskQueue.getSize(); });
}
