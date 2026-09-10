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

// These validation/verification routines are used by both pdnsutil and
// the pdns_server REST API.
// They build error messages, if any, into an object provided by the caller
// (preferably a container if it makes sense to report multiple errors);
// it's up to each caller to decide how to report such errors.

#include "dnsbackend.hh" // DomainInfo

namespace Check
{

// Tuple type used for diagnostic reports.
// The priority is used to tell errors (Logr::Error) from non-fatal
// diagnostics (Logr::Warning)
using diag = std::tuple<Logr::Priority, DNSName, QType, std::string>;

// Validate a view name. Although view names never appear on the wire, we
// restrict them to [a-zA-Z0-9-_. ], with empty names or names with leading
// whitespace or a leading dot forbidden.
bool validateViewName(std::string_view name, std::string& error);

enum RRSetFlags : unsigned int
{
  RRSET_ALLOW_UNDERSCORES = 1 << 0, // Allow underscore in names
  RRSET_CHECK_TTL = 1 << 1, // Check the TTL of the RRset
  RRSET_IGNORE_MISSING_ENT = 1 << 2, // Assume zone rectification follows
};

// Append a list of (severity, record, message) diagnostic tuples to
// [diagnostics] for all zone records in [newrrs] which violate RRset
// constraints.
// NOTE: sorts records [newrrs] in in-place.
//
// The [oldrrs] list of existing records is only used to compute better error
// messages, in order to properly refer to an existing record to explain why
// a given new record is not allowed.
//
//  Constraints being checked:
//   *) no exact duplicates
//   *) no duplicates for QTypes that can only be present once per RRset
//   *) hostnames are hostnames
//   *) no mismatching TTL (if asked in flags)
//
// This routine never assumes [newrrs] contains the complete zone records, and
// thus will not perform checks which require the complete zone knowledge.
void checkRRSet(const std::vector<DNSResourceRecord>& oldrrs, std::vector<DNSResourceRecord>& newrrs, const ZoneName& zone, RRSetFlags flags, std::vector<diag>& diagnostics);

// Check a complete zone contents and metadata.
// NOTE: sorts records [allrrs] in in-place due to the invocation of checkRRSet
// above.
void checkZone(Logr::log_t slog, std::vector<DNSResourceRecord>& allrrs, const ZoneName& zone, DomainInfo::DomainKind kind, RRSetFlags flags, std::vector<diag>& diagnostics);

} // namespace Check
