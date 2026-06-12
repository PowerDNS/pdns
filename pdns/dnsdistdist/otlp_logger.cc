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
#include <exception>
#include <memory>
#include <stdexcept>
#include <thread>

#include "otlp_logger.hh"
#include "dnsdist-logging.hh"
#include "logging.hh"
#include "dolog.hh"
#include "logr.hh"
#include "remote_logger.hh"
#include "threadname.hh"

#if !defined(DISABLE_PROTOBUF) && defined(HAVE_LIBCURL)
#include "minicurl.hh"
#include "protozero-trace.hh"
#include "protozero-otlp.hh"

OTLPLogger::OTLPLogger(std::string address, const size_t interval, const size_t queuesize, const size_t batchSize) :
  d_address(std::move(address)), d_interval(interval), d_batchSize(batchSize)
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
    d_miniCurl = std::make_unique<MiniCurl>("dnsdist/" + std::string(PACKAGE_VERSION));
    break;
  case LoggerType::gRPC:
    throw std::runtime_error("gRPC support is not implemented in the OTLP logger");
  }

  d_logger = dnsdist::logging::getTopLogger("OTLPLogger");
  d_traces.lock()->reserve(queuesize);
  d_thread = std::thread(&OTLPLogger::senderThread, this);
}

// If we get some nice data, queue it
RemoteLoggerInterface::Result OTLPLogger::queueData(const TracesData& data)
{
  auto lockedTraces = d_traces.lock();

  if (lockedTraces->size() >= lockedTraces->capacity()) {
    d_queueFullDrops++;
    return RemoteLoggerInterface::Result::PipeFull;
  }

  lockedTraces->push_back(data);
  return RemoteLoggerInterface::Result::Queued;
}

// When we get bytes (or whatever), send as-is
RemoteLoggerInterface::Result OTLPLogger::queueData(const std::string& data)
{
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
  auto response = d_miniCurl->postURL(d_address, data, d_httpHeaders);
  protozero::pbf_reader reader(response);
  auto exportTraceServiceResponse = pdns::trace::ExportTraceServiceResponse::decode(reader);
  if (exportTraceServiceResponse.partial_success.rejected_spans == 0) {
    return RemoteLoggerInterface::Result::Queued;
  }
  return RemoteLoggerInterface::Result::OtherError;
}

// Returns the number of traces sent, 0 on empty, -1 on error
// TODO: make it do size_t and throw otherwise
int OTLPLogger::sendBatch()
{
  auto lockedTraces = d_traces.lock();
  if (lockedTraces->empty()) {
    return 0;
  }

  pdns::trace::ExportTraceServiceRequest etsr;

  auto sentNum = lockedTraces->size() > d_batchSize ? d_batchSize : lockedTraces->size();
  etsr.resource_spans.reserve(sentNum);

  auto endIt = lockedTraces->begin() + sentNum;
  auto it = lockedTraces->begin();
  while (it != endIt) {
    etsr.resource_spans.insert(etsr.resource_spans.end(), it->resource_spans.begin(), it->resource_spans.end());
    it++;
  }

  std::string buf;
  protozero::pbf_writer writer{buf};
  etsr.encode(writer);

  switch (d_type) {
  case LoggerType::HTTP:
    if (queueHttpData(buf) == RemoteLoggerInterface::Result::Queued) {
      d_framesSent += sentNum;
      lockedTraces->erase(lockedTraces->begin(), endIt);
      d_failedSends = 0;
      return sentNum;
    }
    d_failedSends++;
    if (d_failedSends >= 5) {
      lockedTraces->erase(lockedTraces->begin(), endIt);
      // Not really a queue full, but the best we got
      d_queueFullDrops += sentNum;
      d_failedSends = 0;
    }
    return -1;
  case LoggerType::gRPC:
    // Should never get here
    throw std::runtime_error("gRPC support is not implemented");
  }
}

void OTLPLogger::senderThread()
{
  // TODO: Support OTLP for recursor and auth
  setThreadName("dnsdist/otlplog");

  for (;;) {
    try {
      sendBatch();
    }
    catch (const std::exception& exp) {
      SLOG(
        errlog("Unable to send traces to OTLP receiver %s: %s", d_address, exp.what()),
        d_logger->error(Logr::Error, exp.what(), "Unable to send traces to OTLP receiver", "server.address", Logging::Loggable{d_address}, "failure-count", Logging::Loggable{d_failedSends}));
    }
    if (d_exiting) {
      while (sendBatch() != 0) {}
      return;
    }
    std::this_thread::sleep_for(std::chrono::seconds(d_interval));
  }
}
#endif /* !defined(DISABLE_PROTOBUF) && defined(HAVE_LIBCURL) */
