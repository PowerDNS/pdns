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

namespace Check
{

// Validate a view name. Although view names never appear on the wire, we
// restrict them to [a-zA-Z0-9-_. ], with empty names or names with leading
// whitespace or a leading dot forbidden.
bool validateViewName(std::string_view name, std::string& error);

enum RRSetFlags : unsigned int
{
  RRSET_ALLOW_UNDERSCORES = 1 << 0, // Allow underscore in names
  RRSET_CHECK_TTL = 1 << 1, // Check the TTL of the RRset
};

// Returns the list of errors found for new records which violate RRset
// constraints.
// NOTE: sorts records in-place.
//
//  Constraints being checked:
//   *) no exact duplicates
//   *) no duplicates for QTypes that can only be present once per RRset
//   *) hostnames are hostnames
void checkRRSet(const vector<DNSResourceRecord>& oldrrs, vector<DNSResourceRecord>& allrrs, const ZoneName& zone, RRSetFlags flags, vector<pair<DNSResourceRecord, string>>& errors);

} // namespace Check
