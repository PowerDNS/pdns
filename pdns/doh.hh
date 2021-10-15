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
#include "iputils.hh"
#include "libssl.hh"
#include "noinitvector.hh"
#include "stat_t.hh"

struct DOHServerConfig;

class DOHResponseMapEntry
{
public:
  DOHResponseMapEntry(const std::string& regex, uint16_t status, const PacketBuffer& content, const boost::optional<std::vector<std::pair<std::string, std::string>>>& headers): d_regex(regex), d_customHeaders(headers), d_content(content), d_status(status)
  {
    if (status >= 400 && !d_content.empty() && d_content.at(d_content.size() -1) != 0) {
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

  const boost::optional<std::vector<std::pair<std::string, std::string>>>& getHeaders() const
  {
    return d_customHeaders;
  }

private:
  Regex d_regex;
  boost::optional<std::vector<std::pair<std::string, std::string>>> d_customHeaders;
  PacketBuffer d_content;
  uint16_t d_status;
};

struct DOHFrontend
{
  DOHFrontend()
  {
  }

  std::shared_ptr<DOHServerConfig> d_dsc{nullptr};
  std::shared_ptr<std::vector<std::shared_ptr<DOHResponseMapEntry>>> d_responsesMap;
  TLSConfig d_tlsConfig;
  TLSErrorCounters d_tlsCounters;
  std::string d_serverTokens{"h2o/dnsdist"};
  std::vector<std::pair<std::string, std::string>> d_customResponseHeaders;
  ComboAddress d_local;

  uint32_t d_idleTimeout{30};             // HTTP idle timeout in seconds
  std::vector<std::string> d_urls;

  pdns::stat_t d_httpconnects{0};   // number of TCP/IP connections established
  pdns::stat_t d_getqueries{0};     // valid DNS queries received via GET
  pdns::stat_t d_postqueries{0};    // valid DNS queries received via POST
  pdns::stat_t d_badrequests{0};     // request could not be converted to dns query
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
  uint32_t d_internalPipeBufferSize{1024*1024};
#else
  uint32_t d_internalPipeBufferSize{0};
#endif
  bool d_sendCacheControlHeaders{true};
  bool d_trustForwardedForHeader{false};
  /* whether we require tue query path to exactly match one of configured ones,
     or accept everything below these paths. */
  bool d_exactPathMatching{true};

  time_t getTicketsKeyRotationDelay() const
  {
    return d_tlsConfig.d_ticketsKeyRotationDelay;
  }

  bool isHTTPS() const
  {
    return !d_tlsConfig.d_certKeyPairs.empty();
  }

#ifndef HAVE_DNS_OVER_HTTPS
  void setup()
  {
  }

  void reloadCertificates()
  {
  }

  void rotateTicketsKey(time_t now)
  {
  }

  void loadTicketsKeys(const std::string& keyFile)
  {
  }

  void handleTicketsKeyRotation()
  {
  }

  time_t getNextTicketsKeyRotation() const
  {
    return 0;
  }

  size_t getTicketsKeysCount() const
  {
    size_t res = 0;
    return res;
  }

#else
  void setup();
  void reloadCertificates();

  void rotateTicketsKey(time_t now);
  void loadTicketsKeys(const std::string& keyFile);
  void handleTicketsKeyRotation();
  time_t getNextTicketsKeyRotation() const;
  size_t getTicketsKeysCount() const;
#endif /* HAVE_DNS_OVER_HTTPS */
};

#ifndef HAVE_DNS_OVER_HTTPS
struct DOHUnit
{
};

#else /* HAVE_DNS_OVER_HTTPS */
#include <unordered_map>

#include "dnsdist-idstate.hh"

struct st_h2o_req_t;
struct DownstreamState;

struct DOHUnit
{
  DOHUnit()
  {
    ids.ednsAdded = false;
  }
  DOHUnit(const DOHUnit&) = delete;
  DOHUnit& operator=(const DOHUnit&) = delete;

  void get()
  {
    ++d_refcnt;
  }

  void release()
  {
    if (--d_refcnt == 0) {
      if (self) {
        *self = nullptr;
      }

      delete this;
    }
  }

  void handleUDPResponse(PacketBuffer&& response, IDState&& state);

  IDState ids;
  std::string sni;
  std::string path;
  std::string scheme;
  std::string host;
  std::string contentType;
  std::vector<std::pair<std::string, std::string>> headers;
  PacketBuffer query;
  PacketBuffer response;
  std::shared_ptr<DownstreamState> downstream{nullptr};
  st_h2o_req_t* req{nullptr};
  DOHUnit** self{nullptr};
  DOHServerConfig* dsc{nullptr};
  std::atomic<uint64_t> d_refcnt{1};
  size_t query_at{0};
  size_t proxyProtocolPayloadSize{0};
  int rsock{-1};
  /* the status_code is set from
     processDOHQuery() (which is executed in
     the DOH client thread) so that the correct
     response can be sent in on_dnsdist(),
     after the DOHUnit has been passed back to
     the main DoH thread.
  */
  uint16_t status_code{200};
  /* whether the query was re-sent to the backend over
     TCP after receiving a truncated answer over UDP */
  bool tcp{false};
  bool truncated{false};

  std::string getHTTPPath() const;
  std::string getHTTPHost() const;
  std::string getHTTPScheme() const;
  std::string getHTTPQueryString() const;
  std::unordered_map<std::string, std::string> getHTTPHeaders() const;
  void setHTTPResponse(uint16_t statusCode, PacketBuffer&& body, const std::string& contentType="");
};

#endif /* HAVE_DNS_OVER_HTTPS  */

void handleDOHTimeout(DOHUnit* oldDU);
