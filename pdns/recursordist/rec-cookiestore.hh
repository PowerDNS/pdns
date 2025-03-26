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

/*
  CookieStore is used to keep track of client cookies used for contacting authoritative servers.
  According to RFC 7873 and RFC 9018, it has the following design.

  - Cookies are stored with an auth IP address as primary index and are generated randomly.

  - If the the does not support cookies, this is marked as such and no cookies will be sent to it
    for a period of time. When a cookie is sent again, it must be a newly generated one.

  - A cookie is stored together with the local IP (as rec can have many). If a server is to be
    contacted again, it should use the same bound IP.

  - Although it is perfectly fine for a client cookie to live for a long time, this design will
    flush entries older that a certain period of time, to avoid an ever growing CookieStore.

*/

#include <boost/utility.hpp>
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/key_extractors.hpp>
#include <boost/multi_index/sequenced_index.hpp>

#include "iputils.hh"
#include "ednscookies.hh"

using namespace ::boost::multi_index;

struct CookieEntry
{
  enum class Support : uint8_t
  {
    Unsupported,
    Supported,
    Probing
  };

  static std::string toString(Support support)
  {
    static const std::array<std::string, 4> names = {
      "Unsupported",
      "Supported",
      "Probing"};
    const auto index = static_cast<uint8_t>(support);
    if (index >= names.size()) {
      return "?";
    }
    return names.at(index);
  }

  Support getSupport() const
  {
    return d_support;
  }

  void setSupport(Support support, time_t now) const // modifying mutable field
  {
    d_lastupdate = now;
    d_support = support;
  }

  bool supported() const
  {
    return d_support == Support::Supported;
  }

  ComboAddress d_address;
  mutable ComboAddress d_localaddress; // The address we were bound to, see RFC 9018
  mutable EDNSCookiesOpt d_cookie; // Contains both client and server cookie
  mutable time_t d_lastupdate{};
  mutable Support d_support{Support::Unsupported};
};

class CookieStore : public multi_index_container<CookieEntry,
                                                 indexed_by<ordered_unique<tag<ComboAddress>, member<CookieEntry, ComboAddress, &CookieEntry::d_address>>,
                                                            ordered_non_unique<tag<time_t>, member<CookieEntry, time_t, &CookieEntry::d_lastupdate>>>>
{
public:
  void prune(time_t cutoff);
  static uint64_t dump(const CookieStore&, int fileDesc);
};
