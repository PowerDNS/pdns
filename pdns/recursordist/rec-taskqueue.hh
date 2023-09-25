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

#include <cstdint>
#include <ctime>
#include <qtype.hh>

class DNSName;
union ComboAddress;
class Netmask;

namespace pdns
{
struct ResolveTask;
}
void runTasks(size_t max, bool logErrors);
bool runTaskOnce(bool logErrors);
void pushAlmostExpiredTask(const DNSName& qname, uint16_t qtype, time_t deadline, const Netmask& netmask);
void pushResolveTask(const DNSName& qname, uint16_t qtype, time_t now, time_t deadline, bool forceQMOff);
bool pushTryDoTTask(const DNSName& qname, uint16_t qtype, const ComboAddress& ipAddress, time_t deadline, const DNSName& nsname);
void taskQueueClear();
pdns::ResolveTask taskQueuePop();

// General task stats
uint64_t getTaskPushes();
uint64_t getTaskExpired();
uint64_t getTaskSize();

// Resolve specific stats
uint64_t getResolveTasksPushed();
uint64_t getResolveTasksRun();
uint64_t getResolveTaskExceptions();

// Almost expired specific stats
uint64_t getAlmostExpiredTasksPushed();
uint64_t getAlmostExpiredTasksRun();
uint64_t getAlmostExpiredTaskExceptions();

bool taskQTypeIsSupported(QType qtype);
