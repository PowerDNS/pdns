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

#include <optional>
#include <unordered_map>
#include <set>
#include <string_view>

#include "config.h"
#include "iputils.hh"
#include "libssl.hh"
#include "noinitvector.hh"
#include "stat_t.hh"
#include "tcpiohandler.hh"

namespace dnsdist::doh
{
std::optional<PacketBuffer> getPayloadFromPath(const std::string_view& path);
}

struct DOHServerConfig;

class DOHResponseMapEntry
{
public:
  DOHResponseMapEntry(const std::string& regex, uint16_t status, const PacketBuffer& content, const boost::optional<std::unordered_map<std::string, std::string>>& headers) :
    d_regex(regex), d_customHeaders(headers), d_content(content), d_status(status)
  {
    if (status >= 400 && !d_content.empty() && d_content.at(d_content.size() - 1) != 0) {
      // we need to make sure it's null-terminated
      d_content.push_back(0);
    }
  }

  bool matches(const std::string& path) const
  {
    return d_regex.match(path);
  }

  uint16_t getStatusCode() const
  {
    return d_status;
  }

  const PacketBuffer& getContent() const
  {
    return d_content;
  }

  const boost::optional<std::unordered_map<std::string, std::string>>& getHeaders() const
  {
    return d_customHeaders;
  }

private:
  Regex d_regex;
  boost::optional<std::unordered_map<std::string, std::string>> d_customHeaders;
  PacketBuffer d_content;
  uint16_t d_status;
};

struct DOHFrontend
{
  DOHFrontend()
  {
  }
  DOHFrontend(std::shared_ptr<TLSCtx> tlsCtx) :
    d_tlsContext(std::move(tlsCtx))
  {
  }

  virtual ~DOHFrontend()
  {
  }

  std::shared_ptr<DOHServerConfig> d_dsc{nullptr};
  std::shared_ptr<std::vector<std::shared_ptr<DOHResponseMapEntry>>> d_responsesMap;
  TLSFrontend d_tlsContext{TLSFrontend::ALPN::DoH};
  std::string d_serverTokens{"h2o/dnsdist"};
  std::unordered_map<std::string, std::string> d_customResponseHeaders;
  std::string d_library;

  uint32_t d_idleTimeout{30}; // HTTP idle timeout in seconds
  std::set<std::string, std::less<>> d_urls;

  pdns::stat_t d_httpconnects{0}; // number of TCP/IP connections established
  pdns::stat_t d_getqueries{0}; // valid DNS queries received via GET
  pdns::stat_t d_postqueries{0}; // valid DNS queries received via POST
  pdns::stat_t d_badrequests{0}; // request could not be converted to dns query
  pdns::stat_t d_errorresponses{0}; // dnsdist set 'error' on response
  pdns::stat_t d_redirectresponses{0}; // dnsdist set 'redirect' on response
  pdns::stat_t d_validresponses{0}; // valid responses sent out

  struct HTTPVersionStats
  {
    pdns::stat_t d_nbQueries{0}; // valid DNS queries received
    pdns::stat_t d_nb200Responses{0};
    pdns::stat_t d_nb400Responses{0};
    pdns::stat_t d_nb403Responses{0};
    pdns::stat_t d_nb500Responses{0};
    pdns::stat_t d_nb502Responses{0};
    pdns::stat_t d_nbOtherResponses{0};
  };

  HTTPVersionStats d_http1Stats;
  HTTPVersionStats d_http2Stats;
#ifdef __linux__
  // On Linux this gives us 128k pending queries (default is 8192 queries),
  // which should be enough to deal with huge spikes
  uint32_t d_internalPipeBufferSize{1024 * 1024};
#else
  uint32_t d_internalPipeBufferSize{0};
#endif
  bool d_sendCacheControlHeaders{true};
  bool d_trustForwardedForHeader{false};
  bool d_earlyACLDrop{true};
  /* whether we require tue query path to exactly match one of configured ones,
     or accept everything below these paths. */
  bool d_exactPathMatching{true};
  bool d_keepIncomingHeaders{false};

  time_t getTicketsKeyRotationDelay() const
  {
    return d_tlsContext.d_tlsConfig.d_ticketsKeyRotationDelay;
  }

  bool isHTTPS() const
  {
    return !d_tlsContext.d_tlsConfig.d_certKeyPairs.empty();
  }

#ifndef HAVE_DNS_OVER_HTTPS
  virtual void setup()
  {
  }

  virtual void reloadCertificates()
  {
  }

  virtual void rotateTicketsKey(time_t /* now */)
  {
  }

  virtual void loadTicketsKeys(const std::string& /* keyFile */)
  {
  }

  virtual void loadTicketsKey(const std::string& /* key */)
  {
  }

  virtual void handleTicketsKeyRotation()
  {
  }

  virtual std::string getNextTicketsKeyRotation()
  {
    return std::string();
  }

  virtual size_t getTicketsKeysCount() const
  {
    size_t res = 0;
    return res;
  }

#else
  virtual void setup();
  virtual void reloadCertificates();

  virtual void rotateTicketsKey(time_t now);
  virtual void loadTicketsKeys(const std::string& keyFile);
  virtual void loadTicketsKey(const std::string& key);
  virtual void handleTicketsKeyRotation();
  virtual std::string getNextTicketsKeyRotation() const;
  virtual size_t getTicketsKeysCount();
#endif /* HAVE_DNS_OVER_HTTPS */
};

#include "dnsdist-idstate.hh"

struct DownstreamState;

#ifndef HAVE_DNS_OVER_HTTPS
struct DOHUnitInterface
{
  virtual ~DOHUnitInterface()
  {
  }
  static void handleTimeout(std::unique_ptr<DOHUnitInterface>)
  {
  }

  static void handleUDPResponse(std::unique_ptr<DOHUnitInterface>, PacketBuffer&&, InternalQueryState&&, const std::shared_ptr<DownstreamState>&)
  {
  }
};
#else /* HAVE_DNS_OVER_HTTPS */
struct DOHUnitInterface
{
  virtual ~DOHUnitInterface()
  {
  }

  virtual std::string getHTTPPath() const = 0;
  virtual std::string getHTTPQueryString() const = 0;
  virtual const std::string& getHTTPHost() const = 0;
  virtual const std::string& getHTTPScheme() const = 0;
  virtual const std::unordered_map<std::string, std::string>& getHTTPHeaders() const = 0;
  virtual void setHTTPResponse(uint16_t statusCode, PacketBuffer&& body, const std::string& contentType = "") = 0;
  virtual void handleTimeout() = 0;
  virtual void handleUDPResponse(PacketBuffer&& response, InternalQueryState&& state, const std::shared_ptr<DownstreamState>&) = 0;

  static void handleTimeout(std::unique_ptr<DOHUnitInterface> unit)
  {
    if (unit) {
      auto* ptr = unit.release();
      ptr->handleTimeout();
    }
  }

  static void handleUDPResponse(std::unique_ptr<DOHUnitInterface> unit, PacketBuffer&& response, InternalQueryState&& state, const std::shared_ptr<DownstreamState>& ds)
  {
    if (unit) {
      auto* ptr = unit.release();
      ptr->handleUDPResponse(std::move(response), std::move(state), ds);
    }
  }

  std::shared_ptr<DownstreamState> downstream{nullptr};
};
#endif /* HAVE_DNS_OVER_HTTPS  */
