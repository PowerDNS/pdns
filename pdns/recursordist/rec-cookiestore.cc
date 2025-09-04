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

#include "misc.hh"
#include "rec-cookiestore.hh"

using timebuf_t = std::array<char, 64>;

extern const char* timestamp(time_t arg, timebuf_t& buf); // XXX

void CookieStore::prune(time_t cutoff)
{
  auto& ind = get<time_t>();
  ind.erase(ind.begin(), ind.upper_bound(cutoff));
}

uint64_t CookieStore::dump(int fileDesc) const
{
  int newfd = dup(fileDesc);
  if (newfd == -1) {
    return 0;
  }
  auto filePtr = pdns::UniqueFilePtr(fdopen(newfd, "w"));
  if (!filePtr) {
    close(newfd);
    return 0;
  }
  uint64_t count = 0;

  fprintf(filePtr.get(), "; cookie dump follows\n; server\tlocal\tcookie\tsupport\tts\n");
  for (const auto& entry : *this) {
    count++;
    timebuf_t tmp;
    fprintf(filePtr.get(), "%s\t%s\t%s\t%s\t%s\n",
            entry.d_address.toString().c_str(), entry.d_localaddress.toString().c_str(),
            entry.d_cookie.toDisplayString().c_str(),
            CookieEntry::toString(entry.d_support).c_str(),
            entry.d_lastupdate == std::numeric_limits<time_t>::max() ? "Forever" : timestamp(entry.d_lastupdate, tmp));
  }
  return count;
}
