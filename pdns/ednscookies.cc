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
#include "ednscookies.hh"

bool getEDNSCookiesOptFromString(const string& option, EDNSCookiesOpt* eco)
{
  return getEDNSCookiesOptFromString(option.c_str(), option.length(), eco);
}

bool getEDNSCookiesOptFromString(const char* option, unsigned int len, EDNSCookiesOpt* eco)
{
  if (len != 8 && len < 16)
    return false;
  eco->client = string(option, 8);
  if (len > 8) {
    eco->server = string(option + 8, len - 8);
  }
  return true;
}

string makeEDNSCookiesOptString(const EDNSCookiesOpt& eco)
{
  string ret;
  if (eco.client.length() != 8)
    return ret;
  if (eco.server.length() != 0 && (eco.server.length() < 8 || eco.server.length() > 32))
    return ret;
  ret.assign(eco.client);
  if (eco.server.length() != 0)
    ret.append(eco.server);
  return ret;
}
