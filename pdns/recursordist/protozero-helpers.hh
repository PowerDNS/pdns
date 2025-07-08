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

#include <protozero/pbf_builder.hpp>
#include <protozero/pbf_message.hpp>

#include "iputils.hh"

enum class PBComboAddress : protozero::pbf_tag_type
{
  required_uint32_port = 1,
  required_bytes_address = 2, // family implicit
};

template <typename T>
void encodeComboAddress(protozero::pbf_builder<T>& writer, T type, const ComboAddress& address)
{
  protozero::pbf_builder<PBComboAddress> message(writer, type);

  // Skip all parts except address and port
  message.add_uint32(PBComboAddress::required_uint32_port, address.getPort());
  if (address.sin4.sin_family == AF_INET) {
    message.add_bytes(PBComboAddress::required_bytes_address, reinterpret_cast<const char*>(&address.sin4.sin_addr.s_addr), sizeof(address.sin4.sin_addr.s_addr)); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast): it's the API
  }
  else if (address.sin4.sin_family == AF_INET6) {
    message.add_bytes(PBComboAddress::required_bytes_address, reinterpret_cast<const char*>(&address.sin6.sin6_addr.s6_addr), sizeof(address.sin6.sin6_addr)); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast): it's the API
  }
}

template <typename T>
void decodeComboAddress(protozero::pbf_message<T>& reader, ComboAddress& address)
{
  address.reset();
  protozero::pbf_message<PBComboAddress> message(reader.get_message());

  // Skip all parts except address and port
  if (message.next(PBComboAddress::required_uint32_port)) {
    address.setPort(message.get_uint32());
  }
  else {
    throw std::runtime_error("expected port in protobuf data");
  }
  constexpr auto inet4size = sizeof(address.sin4.sin_addr);
  constexpr auto inet6size = sizeof(address.sin6.sin6_addr);
  if (message.next(PBComboAddress::required_bytes_address)) {
    auto data = message.get_bytes();
    address.sin4.sin_family = data.size() == inet4size ? AF_INET : AF_INET6;
    if (data.size() == inet4size) {
      address.sin4.sin_family = AF_INET;
      memcpy(&address.sin4.sin_addr, data.data(), data.size());
    }
    else if (data.size() == inet6size) {
      address.sin6.sin6_family = AF_INET6;
      memcpy(&address.sin6.sin6_addr, data.data(), data.size());
    }
    else {
      throw std::runtime_error("unexpected address family in protobuf data");
    }
  }
  else {
    throw std::runtime_error("expected address bytes in protobuf data");
  }
}

template <typename T>
void encodeNetmask(protozero::pbf_builder<T>& writer, T type, const Netmask& subnet)
{
  if (!subnet.empty()) {
    writer.add_bytes(type, reinterpret_cast<const char*>(&subnet), sizeof(Netmask)); // NOLINT(cppcoreguidelines-pro-type-reinterpret-cast): it's the API
  }
}

template <typename T>
void decodeNetmask(protozero::pbf_message<T>& message, Netmask& subnet)
{
  auto data = message.get_bytes();
  memcpy(&subnet, data.data(), std::min(sizeof(subnet), data.size()));
}
