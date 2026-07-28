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

#include "config.h"
#if defined(HAVE_DNS_OVER_HTTPS) && defined(HAVE_NGHTTP2)
#include <nghttp2/nghttp2.h>

#include "dnsdist-tcp-upstream.hh"

class IncomingHTTP2Connection : public IncomingTCPConnectionState
{
public:
  using StreamID = int32_t;

  class PendingQuery
  {
  public:
    enum class Method : uint8_t
    {
      Unknown,
      Get,
      Post,
      Unsupported
    };

    PacketBuffer d_buffer;
    PacketBuffer d_response;
    std::string d_path;
    std::string d_scheme;
    std::string d_host;
    std::string d_queryString;
    std::string d_sni;
    std::string d_contentTypeOut;
    std::unique_ptr<HeadersMap> d_headers;
    size_t d_queryPos{0};
    uint32_t d_statusCode{0};
    Method d_method{Method::Unknown};
    bool d_sendingResponse{false};
  };

  IncomingHTTP2Connection(ConnectionInfo&& connectionInfo, TCPClientThreadData& threadData, const struct timeval& now);
  ~IncomingHTTP2Connection() = default;
  void handleIO() override;
  void handleResponse(const struct timeval& now, TCPResponse&& response) override;
  void notifyIOError(const struct timeval& now, TCPResponse&& response) override;
  bool active() const override;

private:
  static ssize_t send_callback(nghttp2_session* session, const uint8_t* data, size_t length, int flags, void* user_data);
  static int on_frame_recv_callback(nghttp2_session* session, const nghttp2_frame* frame, void* user_data);
  static int on_data_chunk_recv_callback(nghttp2_session* session, uint8_t flags, StreamID stream_id, const uint8_t* data, size_t len, void* user_data);
  static int on_stream_close_callback(nghttp2_session* session, StreamID stream_id, uint32_t error_code, void* user_data);
  static int on_header_callback(nghttp2_session* session, const nghttp2_frame* frame, const uint8_t* name, size_t namelen, const uint8_t* value, size_t valuelen, uint8_t flags, void* user_data);
  static int on_begin_headers_callback(nghttp2_session* session, const nghttp2_frame* frame, void* user_data);
  static int on_error_callback(nghttp2_session* session, int lib_error_code, const char* msg, size_t len, void* user_data);
  static void handleReadableIOCallback(int descriptor, FDMultiplexer::funcparam_t& param);
  static void handleWritableIOCallback(int descriptor, FDMultiplexer::funcparam_t& param);

  static constexpr size_t s_initialReceiveBufferSize{256U};

  IOState sendResponse(const struct timeval& now, TCPResponse&& response) override;
  bool forwardViaUDPFirst() const override
  {
    return true;
  }
  void restoreDOHUnit(std::unique_ptr<DOHUnitInterface>&&) override;
  std::unique_ptr<DOHUnitInterface> getDOHUnit(uint32_t streamID) override;

  void stopIO();
  std::unordered_map<StreamID, PendingQuery>::iterator getStreamContext(StreamID streamID);
  uint32_t getConcurrentStreamsCount() const;
  void updateIO(IOState newState, const timeval& now) override;
  void updateIO(IOState newState, const FDMultiplexer::callbackfunc_t& callback);
  void handleIOError();
  bool sendResponse(StreamID streamID, PendingQuery& context, uint16_t responseCode, const HeadersMap& customResponseHeaders, const std::string& contentType = "", bool addContentType = true);
  void handleIncomingQuery(PendingQuery&& query, StreamID streamID);
  bool checkALPN();
  IOState readHTTPData();
  void handleConnectionReady();
  IOState handleHandshake(const struct timeval& now) override;
  bool hasPendingWrite() const;
  void writeToSocket(bool socketReady);
  boost::optional<struct timeval> getIdleClientReadTTD(struct timeval now) const;

  std::unique_ptr<nghttp2_session, decltype(&nghttp2_session_del)> d_session{nullptr, nghttp2_session_del};
  std::unordered_map<StreamID, PendingQuery> d_currentStreams;
  std::unordered_set<StreamID> d_killedStreams;
  PacketBuffer d_out;
  PacketBuffer d_in;
  size_t d_outPos{0};
  /* this connection is done, the remote end has closed the connection
     or something like that. We do not want to try to write to it. */
  bool d_connectionDied{false};
  /* we are done reading from this connection, but we might still want to
     write to it to close it properly */
  bool d_connectionClosing{false};
  /* Whether we are still waiting for more data to be buffered
     before writing to the socket (false) or not. */
  bool d_needFlush{false};
  /* Whether we have data that we want to write to the socket,
     but the socket is full. */
  bool d_pendingWrite{false};
  /* Whether we are currently inside the readHTTPData function,
     which is not reentrant and could be called from itself via
     the nghttp2 callbacks */
  bool d_inReadFunction{false};
};

class NGHTTP2Headers
{
public:
  enum class HeaderConstantIndexes
  {
    OK_200_VALUE = 0,
    METHOD_NAME,
    METHOD_VALUE,
    SCHEME_NAME,
    SCHEME_VALUE,
    AUTHORITY_NAME,
    X_FORWARDED_FOR_NAME,
    PATH_NAME,
    CONTENT_LENGTH_NAME,
    STATUS_NAME,
    LOCATION_NAME,
    ACCEPT_NAME,
    ACCEPT_VALUE,
    CACHE_CONTROL_NAME,
    CONTENT_TYPE_NAME,
    CONTENT_TYPE_VALUE,
    USER_AGENT_NAME,
    USER_AGENT_VALUE,
    X_FORWARDED_PORT_NAME,
    X_FORWARDED_PROTO_NAME,
    X_FORWARDED_PROTO_VALUE_DNS_OVER_UDP,
    X_FORWARDED_PROTO_VALUE_DNS_OVER_TCP,
    X_FORWARDED_PROTO_VALUE_DNS_OVER_TLS,
    X_FORWARDED_PROTO_VALUE_DNS_OVER_HTTP,
    X_FORWARDED_PROTO_VALUE_DNS_OVER_HTTPS,
    COUNT
  };

  static void addStaticHeader(std::vector<nghttp2_nv>& headers, HeaderConstantIndexes nameKey, HeaderConstantIndexes valueKey);
  static void addDynamicHeader(std::vector<nghttp2_nv>& headers, HeaderConstantIndexes nameKey, const std::string_view& value);
  static void addCustomDynamicHeader(std::vector<nghttp2_nv>& headers, const std::string& name, const std::string_view& value);
};

#endif /* HAVE_DNS_OVER_HTTPS && HAVE_NGHTTP2 */
