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
#include "dnsdist-rules.hh"

std::atomic<uint64_t> LuaFFIPerThreadRule::s_functionsCounter = 0;
thread_local std::map<uint64_t, LuaFFIPerThreadRule::PerThreadState> LuaFFIPerThreadRule::t_perThreadStates;

HTTPHeaderRule::HTTPHeaderRule(const std::string& header, const std::string& regex) :
  d_header(toLower(header)), d_regex(regex), d_visual("http[" + header + "] ~ " + regex)
{
#if !defined(HAVE_DNS_OVER_HTTPS) && !defined(HAVE_DNS_OVER_HTTP3)
  throw std::runtime_error("Using HTTPHeaderRule while DoH support is not enabled");
#endif /* HAVE_DNS_OVER_HTTPS || HAVE_DNS_OVER_HTTP3 */
}

bool HTTPHeaderRule::matches(const DNSQuestion* dnsQuestion) const
{
#if defined(HAVE_DNS_OVER_HTTPS)
  if (dnsQuestion->ids.du) {
    const auto& headers = dnsQuestion->ids.du->getHTTPHeaders();
    for (const auto& header : headers) {
      if (header.first == d_header) {
        return d_regex.match(header.second);
      }
    }
    return false;
  }
#endif /* HAVE_DNS_OVER_HTTPS */
#if defined(HAVE_DNS_OVER_HTTP3)
  if (dnsQuestion->ids.doh3u) {
    const auto& headers = dnsQuestion->ids.doh3u->getHTTPHeaders();
    for (const auto& header : headers) {
      if (header.first == d_header) {
        return d_regex.match(header.second);
      }
    }
    return false;
  }
#endif /* defined(HAVE_DNS_OVER_HTTP3) */
  return false;
}

string HTTPHeaderRule::toString() const
{
  return d_visual;
}

HTTPPathRule::HTTPPathRule(std::string path) :
  d_path(std::move(path))
{
#if !defined(HAVE_DNS_OVER_HTTPS) && !defined(HAVE_DNS_OVER_HTTP3)
  throw std::runtime_error("Using HTTPPathRule while DoH support is not enabled");
#endif /* HAVE_DNS_OVER_HTTPS || HAVE_DNS_OVER_HTTP3 */
}

bool HTTPPathRule::matches(const DNSQuestion* dnsQuestion) const
{
#if defined(HAVE_DNS_OVER_HTTPS)
  if (dnsQuestion->ids.du) {
    const auto path = dnsQuestion->ids.du->getHTTPPath();
    return d_path == path;
  }
#endif /* HAVE_DNS_OVER_HTTPS */
#if defined(HAVE_DNS_OVER_HTTP3)
  if (dnsQuestion->ids.doh3u) {
    return dnsQuestion->ids.doh3u->getHTTPPath() == d_path;
  }
#endif /* defined(HAVE_DNS_OVER_HTTP3) */
  return false;

}

string HTTPPathRule::toString() const
{
  return "url path == " + d_path;
}

HTTPPathRegexRule::HTTPPathRegexRule(const std::string& regex) :
  d_regex(regex), d_visual("http path ~ " + regex)
{
#if !defined(HAVE_DNS_OVER_HTTPS) && !defined(HAVE_DNS_OVER_HTTP3)
  throw std::runtime_error("Using HTTPRegexRule while DoH support is not enabled");
#endif /* HAVE_DNS_OVER_HTTPS || HAVE_DNS_OVER_HTTP3 */
}

bool HTTPPathRegexRule::matches(const DNSQuestion* dnsQuestion) const
{
#if defined(HAVE_DNS_OVER_HTTPS)
  if (dnsQuestion->ids.du) {
    const auto path = dnsQuestion->ids.du->getHTTPPath();
    return d_regex.match(path);
  }
#endif /* HAVE_DNS_OVER_HTTPS */
#if defined(HAVE_DNS_OVER_HTTP3)
  if (dnsQuestion->ids.doh3u) {
    return d_regex.match(dnsQuestion->ids.doh3u->getHTTPPath());
  }
  return false;
#endif /* HAVE_DNS_OVER_HTTP3 */
  return false;
}

string HTTPPathRegexRule::toString() const
{
  return d_visual;
}
