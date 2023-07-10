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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "ednscookies.hh"
#include "misc.hh"

#ifdef HAVE_CRYPTO_SHORTHASH
#include <sodium.h>
#endif

EDNSCookiesOpt::EDNSCookiesOpt(const std::string& option)
{
  getEDNSCookiesOptFromString(option.c_str(), option.length());
}

EDNSCookiesOpt::EDNSCookiesOpt(const char* option, unsigned int len)
{
  getEDNSCookiesOptFromString(option, len);
}

bool EDNSCookiesOpt::makeFromString(const std::string& option)
{
  getEDNSCookiesOptFromString(option.c_str(), option.length());
  return isWellFormed();
}

bool EDNSCookiesOpt::makeFromString(const char* option, unsigned int len)
{
  getEDNSCookiesOptFromString(option, len);
  return isWellFormed();
}

string EDNSCookiesOpt::makeOptString() const
{
  string ret;
  if (!isWellFormed())
    return ret;
  ret.assign(client);
  if (server.length() != 0)
    ret.append(server);
  return ret;
}

void EDNSCookiesOpt::getEDNSCookiesOptFromString(const char* option, unsigned int len)
{
  client.clear();
  server.clear();
  if (len < 8)
    return;
  client = string(option, 8);
  if (len > 8) {
    server = string(option + 8, len - 8);
  }
}

bool EDNSCookiesOpt::isValid([[maybe_unused]] const string& secret, [[maybe_unused]] const ComboAddress& source) const
{
#ifdef HAVE_CRYPTO_SHORTHASH
  if (server.length() != 16 || client.length() != 8) {
    return false;
  }
  if (server[0] != '\x01') {
    // Version is not 1, can't verify
    return false;
  }
  uint32_t ts;
  memcpy(&ts, &server[4], sizeof(ts));
  ts = ntohl(ts);
  // coverity[store_truncates_time_t]
  uint32_t now = static_cast<uint32_t>(time(nullptr));
  // RFC 9018 section 4.3:
  //    The DNS server
  //    SHOULD allow cookies within a 1-hour period in the past and a
  //    5-minute period into the future
  if (rfc1982LessThan(now + 300, ts) && rfc1982LessThan(ts + 3600, now)) {
    return false;
  }
  if (secret.length() != crypto_shorthash_KEYBYTES) {
    return false;
  }

  string toHash = client + server.substr(0, 8) + source.toByteString();
  string hashResult;
  hashResult.resize(8);
  crypto_shorthash(
    reinterpret_cast<unsigned char*>(&hashResult[0]),
    reinterpret_cast<const unsigned char*>(&toHash[0]),
    toHash.length(),
    reinterpret_cast<const unsigned char*>(&secret[0]));
  return constantTimeStringEquals(server.substr(8), hashResult);
#else
  return false;
#endif
}

bool EDNSCookiesOpt::shouldRefresh() const
{
  if (server.size() < 16) {
    return true;
  }
  uint32_t ts;
  memcpy(&ts, &server[4], sizeof(ts));
  ts = ntohl(ts);
  // coverity[store_truncates_time_t]
  uint32_t now = static_cast<uint32_t>(time(nullptr));
  // RFC 9018 section 4.3:
  //    The DNS server
  //    SHOULD allow cookies within a 1-hour period in the past and a
  //    5-minute period into the future
  // If this is not the case, we need to refresh
  if (rfc1982LessThan(now + 300, ts) && rfc1982LessThan(ts + 3600, now)) {
    return true;
  }

  // RFC 9018 section 4.3:
  //    The DNS server SHOULD generate a new Server Cookie at least if the
  //     received Server Cookie from the client is more than half an hour old
  return rfc1982LessThan(ts + 1800, now);
}

bool EDNSCookiesOpt::makeServerCookie([[maybe_unused]] const string& secret, [[maybe_unused]] const ComboAddress& source)
{
#ifdef HAVE_CRYPTO_SHORTHASH
  static_assert(EDNSCookieSecretSize == crypto_shorthash_KEYBYTES * 2, "The EDNSCookieSecretSize is not twice crypto_shorthash_KEYBYTES");

  if (isValid(secret, source) && !shouldRefresh()) {
    return true;
  }

  if (secret.length() != crypto_shorthash_KEYBYTES) {
    return false;
  }

  server.clear();
  server.reserve(16);
  server = "\x01"; // Version
  server.resize(4, '\0'); // 3 reserved bytes
  // coverity[store_truncates_time_t]
  uint32_t now = htonl(static_cast<uint32_t>(time(nullptr)));
  server += string(reinterpret_cast<const char*>(&now), sizeof(now));
  server.resize(8);

  string toHash = client;
  toHash += server;
  toHash += source.toByteString();
  server.resize(16);
  crypto_shorthash(
    reinterpret_cast<unsigned char*>(&server[8]),
    reinterpret_cast<const unsigned char*>(&toHash[0]),
    toHash.length(),
    reinterpret_cast<const unsigned char*>(&secret[0]));
  return true;
#else
  return false;
#endif
}
