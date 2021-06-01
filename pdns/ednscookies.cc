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
#include "config.h"
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
  if (client.length() != 8)
    return ret;
  if (server.length() != 0 && (server.length() < 8 || server.length() > 32))
    return ret;
  ret.assign(client);
  if (server.length() != 0)
    ret.append(server);
  return ret;
}

void EDNSCookiesOpt::getEDNSCookiesOptFromString(const char* option, unsigned int len)
{
  checked = false;
  valid = false;
  should_refresh = false;
  client.clear();
  server.clear();
  if (len < 8)
    return;
  client = string(option, 8);
  if (len > 8) {
    server = string(option + 8, len - 8);
  }
}

bool EDNSCookiesOpt::isValid(const string& secret, const ComboAddress& source)
{
#ifdef HAVE_CRYPTO_SHORTHASH
  if (checked && valid) {
    // Ignore the new check, we already validated it
    // XXX this _might_ not be the best behaviour though...
    return valid;
  }
  checked = true;
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
  uint32_t now = static_cast<uint32_t>(time(nullptr));
  if (rfc1982LessThan(now + 300, ts) && rfc1982LessThan(ts + 3600, now)) {
    return false;
  }
  if (rfc1982LessThan(ts + 1800, now)) {
    // RFC 9018 section 4.3:
    //    The DNS server SHOULD generate a new Server Cookie at least if the
    //     received Server Cookie from the client is more than half an hour old
    should_refresh = true;
  }
  if (secret.length() != crypto_shorthash_KEYBYTES) {
    // XXX should we throw std::range_error here?
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
  valid = (server.substr(8) == hashResult);
  return valid;
#else
  return false;
#endif
}

bool EDNSCookiesOpt::makeServerCookie(const string& secret, const ComboAddress& source)
{
#ifdef HAVE_CRYPTO_SHORTHASH
  if (valid && !should_refresh) {
    return true;
  }
  checked = false;
  valid = false;
  should_refresh = false;

  if (secret.length() != crypto_shorthash_KEYBYTES) {
    return false;
  }

  server.clear();
  server = "\x01"; // Version
  server.resize(4, '\0'); // 3 reserved bytes
  uint32_t now = htonl(static_cast<uint32_t>(time(nullptr)));
  server += string(reinterpret_cast<const char*>(&now), 4);
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
  checked = true;
  valid = true;
  should_refresh = false;
  return true;
#else
  return false;
#endif
}
