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
#include "iputils.hh"

struct EDNSCookiesOpt
{
  static const size_t EDNSCookieSecretSize = 32;
  static const size_t EDNSCookieOptSize = 24;

  EDNSCookiesOpt(){};
  EDNSCookiesOpt(const std::string& option);
  EDNSCookiesOpt(const char* option, unsigned int len);

  bool makeFromString(const std::string& option);
  bool makeFromString(const char* option, unsigned int len);

  size_t size() const
  {
    return server.size() + client.size();
  }

  bool isWellFormed() const
  {
    // RFC7873 section 5.2.2
    //    In summary, valid cookie lengths are 8 and 16 to 40 inclusive.
    return (
      client.size() == 8 && (server.size() == 0 || (server.size() >= 8 && server.size() <= 32)));
  }

  bool isValid(const string& secret, const ComboAddress& source) const;
  bool makeServerCookie(const string& secret, const ComboAddress& source);
  string makeOptString() const;
  string getServer() const
  {
    return server;
  }
  string getClient() const
  {
    return client;
  }

private:
  bool shouldRefresh() const;

  // the client cookie
  string client;
  // the server cookie
  string server;

  void getEDNSCookiesOptFromString(const char* option, unsigned int len);
};
