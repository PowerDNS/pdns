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

#include "dnsdist-udp.hh"
#include "dolog.hh"
#include "dnsdist-configuration.hh"

namespace dnsdist::udp
{
static std::string contextToStr(Context context)
{
  if (context == Context::Frontend) {
    return "frontend";
  }
  if (context == Context::Backend) {
    return "backend";
  }

  return "";
}

void setUDPSocketBufferSizes(int socketDesc, const Logr::Logger& logger, Context context, const ComboAddress& addr)
{
  const auto& immutableConfig = dnsdist::configuration::getImmutableConfiguration();
  if (immutableConfig.d_socketUDPSendBuffer > 0) {
    try {
      setSocketSendBuffer(socketDesc, immutableConfig.d_socketUDPSendBuffer);
    }
    catch (const std::exception& e) {
      if (context == Context::Frontend) {
        SLOG(warnlog(e.what()),
             logger.error(Logr::Warning, e.what(), "Failed to raise send buffer size on UDP socket", "frontend.address", Logging::Loggable(addr)));
      }
    }
  }
  else {
    try {
      auto result = raiseSocketSendBufferToMax(socketDesc);
      if (result > 0 && context == Context::Frontend) {
        SLOG(infolog("Raised send buffer to %u for %s address '%s'", result, contextToStr(context), addr.toStringWithPort()),
             logger.info(Logr::Info, "Raised send buffer size", "frontend.address", Logging::Loggable(addr), "network.send_buffer_size", Logging::Loggable(result)));
      }
    }
    catch (const std::exception& e) {
      if (context == Context::Frontend) {
        SLOG(warnlog(e.what()),
             logger.error(Logr::Warning, e.what(), "Failed to raise send buffer size on UDP socket", "frontend.address", Logging::Loggable(addr)));
      }
    }
  }

  if (immutableConfig.d_socketUDPRecvBuffer > 0) {
    try {
      setSocketReceiveBuffer(socketDesc, immutableConfig.d_socketUDPRecvBuffer);
    }
    catch (const std::exception& e) {
      if (context == Context::Frontend) {
        SLOG(warnlog(e.what()),
             logger.error(Logr::Warning, e.what(), "Failed to raise receive buffer size on UDP socket", "frontend.address", Logging::Loggable(addr)));
      }
    }
  }
  else {
    try {
      auto result = raiseSocketReceiveBufferToMax(socketDesc);
      if (result > 0 && context == Context::Frontend) {
        SLOG(infolog("Raised receive buffer to %u for address '%s'", result, addr.toStringWithPort()),
             logger.info(Logr::Info, "Raised receive buffer size", "frontend.address", Logging::Loggable(addr), "buffer_size", Logging::Loggable(result)));
      }
    }
    catch (const std::exception& e) {
      if (context == Context::Frontend) {
        SLOG(warnlog(e.what()),
             logger.error(Logr::Warning, e.what(), "Failed to raise receive buffer size on UDP socket", "frontend.address", Logging::Loggable(addr)));
      }
    }
  }
}

} // dnsdist::udp
