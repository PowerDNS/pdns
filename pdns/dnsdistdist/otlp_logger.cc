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
#include <memory>
#include <stdexcept>

#include "otlp_logger.hh"
#include "remote_logger.hh"

#if !defined(DISABLE_PROTOBUF) && defined(HAVE_LIBCURL)
#include "minicurl.hh"
#include "protozero-trace.hh"
#include "protozero-otlp.hh"

OTLPLogger::OTLPLogger(std::string address) :
  d_address(std::move(address))
{
  LoggerType loggerType;
  if (d_address.find("http://") == 0 || d_address.find("https://") == 0) {
    loggerType = LoggerType::HTTP;
  }
  else if (d_address.find("grpc://") == 0 || d_address.find("grpcs://") == 0) {
    // XXX: this is not the actual scheme, see https://github.com/grpc/grpc/blob/master/doc/naming.md
    loggerType = LoggerType::gRPC;
  }
  else {
    throw std::runtime_error("Can not determine OTLP logger type from address " + address);
  }
  d_type = loggerType;

  switch (d_type) {
    case LoggerType::HTTP:
      d_httpConn = std::make_unique<MiniCurl>("dnsdist/" + std::string(PACKAGE_VERSION));
      break;
    case LoggerType::gRPC:
      throw std::runtime_error("gRPC support is not implemented");
  }
}

RemoteLoggerInterface::Result OTLPLogger::queueData(const pdns::trace::TracesData& data)
{
  pdns::trace::ExportTraceServiceRequest req = {
    .resource_spans = data.resource_spans
  };
  std::string buf;
  protozero::pbf_writer writer(buf);
  req.encode(writer);
  return queueData(buf);
}

RemoteLoggerInterface::Result OTLPLogger::queueData(const std::string& data)
{
  // TODO: Proper queuing, batching, and retries
  switch (d_type) {
  case LoggerType::HTTP:
    return queueHttpData(data);
  case LoggerType::gRPC:
    // Should never get here
    throw std::runtime_error("gRPC support is not implemented");
  }
}

RemoteLoggerInterface::Result OTLPLogger::queueHttpData(const std::string& data)
{
  auto response = d_httpConn->postURL(d_address, data, d_httpHeaders);
  std::cout<<response<<std::endl;
  protozero::pbf_reader reader(response);
  auto exportTraceServiceResponse = pdns::trace::ExportTraceServiceResponse::decode(reader);
  if (exportTraceServiceResponse.partial_success.rejected_spans == 0) {
    return RemoteLoggerInterface::Result::Queued;
  }
  return RemoteLoggerInterface::Result::OtherError;
}
#endif /* !defined(DISABLE_PROTOBUF) && defined(HAVE_LIBCURL) */
