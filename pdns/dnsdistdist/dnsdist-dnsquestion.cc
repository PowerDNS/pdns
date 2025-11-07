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
#include "dnsdist.hh"
#include "dnsdist-configuration.hh"
#include "dnsdist-dnsparser.hh"

std::string DNSQuestion::getTrailingData() const
{
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  const auto* message = reinterpret_cast<const char*>(this->getData().data());
  const uint16_t messageLen = getDNSPacketLength(message, this->getData().size());
  // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
  return {message + messageLen, this->getData().size() - messageLen};
}

bool DNSQuestion::setTrailingData(const std::string& tail)
{
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  const char* message = reinterpret_cast<const char*>(this->data.data());
  const uint16_t messageLen = getDNSPacketLength(message, this->data.size());
  this->data.resize(messageLen);
  if (!tail.empty()) {
    if (!hasRoomFor(tail.size())) {
      return false;
    }
    this->data.insert(this->data.end(), tail.begin(), tail.end());
  }
  return true;
}

bool DNSQuestion::editHeader(const std::function<bool(dnsheader&)>& editFunction)
{
  if (data.size() < sizeof(dnsheader)) {
    throw std::runtime_error("Trying to access the dnsheader of a too small (" + std::to_string(data.size()) + ") DNSQuestion buffer");
  }
  return dnsdist::PacketMangling::editDNSHeaderFromPacket(data, editFunction);
}

DNSQuestion::DNSQuestion(InternalQueryState& ids_, PacketBuffer& data_) :
  data(data_), ids(ids_), ecsPrefixLength(ids.origRemote.sin4.sin_family == AF_INET ? dnsdist::configuration::getCurrentRuntimeConfiguration().d_ECSSourcePrefixV4 : dnsdist::configuration::getCurrentRuntimeConfiguration().d_ECSSourcePrefixV6), ecsOverride(dnsdist::configuration::getCurrentRuntimeConfiguration().d_ecsOverride)
{
}

std::shared_ptr<const Logr::Logger> DNSQuestion::getThisLogger() const
{
  if (d_logger) {
    return d_logger;
  }
  auto logger = dnsdist::logging::getTopLogger();
  logger = logger->withValues("qname", Logging::Loggable(ids.qname), "qtype", Logging::Loggable(QType(ids.qtype)), "qclass", Logging::Loggable(QClass(ids.qclass)), "source", Logging::Loggable(ids.origRemote), "destination", Logging::Loggable(ids.origDest), "proto", Logging::Loggable(ids.protocol));
  return logger;
}

std::shared_ptr<const Logr::Logger> DNSQuestion::getLogger() const
{
  return getThisLogger();
}

std::shared_ptr<const Logr::Logger> DNSQuestion::getLogger()
{
  if (d_logger) {
    return d_logger;
  }
  d_logger = getThisLogger();
  return d_logger;
}
