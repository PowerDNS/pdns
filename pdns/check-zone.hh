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

class CheckException : public runtime_error
{
public:
  CheckException(const string& what_arg) :
    runtime_error(what_arg) {}
};

namespace Check
{

/** Throws CheckException if records which violate RRset constraints are present.
 *  NOTE: sorts records in-place.
 *
 *  Constraints being checked:
 *   *) no exact duplicates
 *   *) no duplicates for QTypes that can only be present once per RRset
 *   *) hostnames are hostnames
 */
void checkRRSet(vector<DNSResourceRecord>& records, const ZoneName& zone);

} // namespace Check
