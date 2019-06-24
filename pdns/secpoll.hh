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
#include <string>
#include <vector>
#include "dnsrecords.hh"

/* Parses the result of a security poll, will throw a PDNSException when it could not be parsed, secPollStatus is
 * set correctly regardless whether or not an exception was thrown.
 *
 * res: DNS Rcode result from the secpoll
 * ret: Records returned during secpoll
 * secPollStatus: The actual secpoll status, pass the current status in here and it is changed to the new status
 * secPollMessage: Will be cleared and filled with the message from the secpoll message
 */
void processSecPoll(const int res, const std::vector<DNSRecord> &ret, int &secPollStatus, std::string &secPollMessage);
bool isReleaseVersion(const std::string &version);
