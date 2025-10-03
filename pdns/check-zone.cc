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

#include "dns.hh"
#include "dnsrecords.hh"

#include "check-zone.hh"

namespace Check
{

bool validateViewName(std::string_view name, std::string& error)
{
  if (name.empty()) {
    error = "Empty view names are not allowed";
    return false;
  }

  if (auto pos = name.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890 _-."); pos != std::string_view::npos) {
    error = std::string("View name contains forbidden character '") + name[pos] + "' at position " + std::to_string(pos);
    return false;
  }

  if (name[0] == '.') {
    error = "View names are not allowed to start with a dot";
    return false;
  }

  if (name[0] == ' ') {
    error = "View names are not allowed to start with a space";
    return false;
  }

  return true;
}

} // namespace Check
