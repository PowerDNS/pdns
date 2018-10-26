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
#include "namespaces.hh"
#include "validate.hh"
#include "logger.hh"

/* Off: 3.x behaviour, we do no DNSSEC, no EDNS
   ProcessNoValidate: we gather DNSSEC records on all queries, but we will never validate
   Process: we gather DNSSEC records on all queries, if you do ad=1, we'll validate for you (unless you set cd=1)
   ValidateForLog: Process + validate all answers, but only log failures
   ValidateAll: DNSSEC issue -> servfail
*/

enum class DNSSECMode { Off, Process, ProcessNoValidate, ValidateForLog, ValidateAll };
extern DNSSECMode g_dnssecmode;
extern bool g_dnssecLogBogus;

bool checkDNSSECDisabled();
bool warnIfDNSSECDisabled(const string& msg);
vState increaseDNSSECStateCounter(const vState& state);
bool updateTrustAnchorsFromFile(const std::string &fname, map<DNSName, dsmap_t> &dsAnchors);
