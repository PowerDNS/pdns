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

#include "auth-querycache.hh"
#include "auth-packetcache.hh"

extern AuthPacketCache PC;
extern AuthQueryCache QC;

/* empty all caches */
uint64_t purgeAuthCaches()
{
  uint64_t ret = 0;
  ret += PC.purge();
  ret += QC.purge();
  return ret;
}

/* remove specific entries from all caches, can be $ terminated */
uint64_t purgeAuthCaches(const std::string& match)
{
  uint64_t ret = 0;
  ret += PC.purge(match);
  ret += QC.purge(match);
  return ret;
}

/* remove specific entries from all caches, no wildcard matching */
uint64_t purgeAuthCachesExact(const DNSName& qname)
{
  uint64_t ret = 0;
  ret += PC.purgeExact(qname);
  ret += QC.purgeExact(qname);
  return ret;
}
