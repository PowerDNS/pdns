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

/* Off: 3.x behaviour, no DNSSEC, no EDNS
 * Process: Set DO on outgoing queries, return RRSIGs and NSEC(3) on +DO from clients
 * ClientOnly: Like Process, but validate as well if the client sets +DO or +AD
 * Validate: Validate all answers
 */
enum class DNSSECValidationMode { Off, Process, ClientOnly, Validate };
extern DNSSECValidationMode g_dnssecMode;

/* Off: Never send out SERVFAIL on a Bogus
 * On: Always send out SERVFAIL on a Bogus
 * ClientOnly: Send SERVFAIL on a bogus if the client query had +AD or +DO set
 *
 * note: a +CD from a client will not yield a DNSSEC SERVFAIL
 */
enum class DNSSECBogusServfailMode { Off, On, ClientOnly };
extern DNSSECBogusServfailMode g_dnssecBogusServfailMode;

bool checkDNSSECDisabled();
bool warnIfDNSSECDisabled(const string& msg);
vState increaseDNSSECStateCounter(const vState& state);
