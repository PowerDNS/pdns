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
#include "remote_logger.hh"
#include <memory>

#if !defined(DISABLE_PROTOBUF) && defined(HAVE_LIBCURL)
#include <memory>

#include "logr.hh"
#include "minicurl.hh"
class OTLPLogger : public RemoteLoggerInterface
{
public:
  enum class LoggerType : uint8_t
  {
    HTTP,
    gRPC,
  };

  OTLPLogger(std::string address);
  OTLPLogger(const OTLPLogger&) = delete;
  OTLPLogger(OTLPLogger&&) = delete;
  OTLPLogger& operator=(const OTLPLogger&) = delete;
  OTLPLogger& operator=(OTLPLogger&&) = delete;
  ~OTLPLogger() override {};

  [[nodiscard]] RemoteLoggerInterface::Result queueData(const std::string& data) override;
  [[nodiscard]] RemoteLoggerInterface::Result queueData(const pdns::trace::TracesData& data);

  [[nodiscard]] std::string address() const override
  {
    return d_address;
  }

  [[nodiscard]] std::string name() const override
  {
    return "OTLP";
  }

  [[nodiscard]] std::string toString() override
  {
    return "OTLPLogger to " + d_address;
  }

  [[nodiscard]] RemoteLoggerInterface::Stats getStats() override
  {
    return Stats{.d_queued = 0,
                 .d_pipeFull = 0,
                 .d_tooLarge = 0,
                 .d_otherError = 0};
  }

private:
  LoggerType d_type;
  std::string d_address;

  std::unique_ptr<MiniCurl> d_httpConn{nullptr};
  MiniCurl::MiniCurlHeaders d_httpHeaders{{"Content-Type", "application/x-protobuf"}};
  [[nodiscard]] RemoteLoggerInterface::Result queueHttpData(const std::string& data);
};
#else
class OTLPLogger : public RemoteLoggerInterface
{
  OTLPLogger(const OTLPLogger&) = delete;
  OTLPLogger(OTLPLogger&&) = delete;
  OTLPLogger& operator=(const OTLPLogger&) = delete;
  OTLPLogger& operator=(OTLPLogger&&) = delete;

public:
  [[nodiscard]] RemoteLoggerInterface::Result queueData([[maybe_unused]] const std::string& data) override
  {
    return RemoteLogger::Result::Queued;
  }
  RemoteLoggerInterface::Result queueData([[maybe_unused]] const TracesData& data)
  {
    return RemoteLogger::Result::Queued;
  }
};
#endif /* !defined(DISABLE_PROTOBUF) && defined(HAVE_LIBCURL) */
