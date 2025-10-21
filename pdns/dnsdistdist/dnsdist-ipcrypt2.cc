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

#ifdef HAVE_IPCRYPT2
#include <memory>
#endif
#include <stdexcept>
#include <string>
#include <sys/socket.h>

#include "dnsdist-ipcrypt2.hh"
#ifdef HAVE_IPCRYPT2
#include "ipcrypt2.h"
#endif
#include "iputils.hh"

// ipcrypt2 namespace does not have to be dnsdist-specific
namespace pdns::ipcrypt2
{
IPCrypt2::IPCrypt2([[maybe_unused]] const IPCryptMethod& method, [[maybe_unused]] const std::string& key) :
  d_method(method)
{
#ifdef HAVE_IPCRYPT2
  switch (method) {
  case IPCryptMethod::pfx: {
    if (key.size() != IPCRYPT_PFX_KEYBYTES) {
      throw std::runtime_error("Key for IPCrypt PFX method is not " + std::to_string(IPCRYPT_PFX_KEYBYTES) + " bytes");
    }
    d_ipcryptCtxPfx = std::make_unique<IPCryptPFX>();
    auto ret = ipcrypt_pfx_init(d_ipcryptCtxPfx.get(), reinterpret_cast<const uint8_t*>(key.data()));
    if (ret != 0) {
      throw std::runtime_error("Could not initialize IPCrypt2 PFX context");
    }
  } break;
  default:
    throw std::runtime_error("Unsupported IPCrypt2 method");
    break;
  }
#else
  throw std::runtime_error("IPCrypt2 is not supported");
#endif
}

IPCrypt2::~IPCrypt2()
{
#ifdef HAVE_IPCRYPT2
  switch (d_method) {
  case IPCryptMethod::pfx:
    if (d_ipcryptCtxPfx != nullptr) {
      ipcrypt_pfx_deinit(d_ipcryptCtxPfx.get());
    }
    break;
  default:
    return;
  }
#endif
};

ComboAddress IPCrypt2::encrypt([[maybe_unused]] const ComboAddress& address) const // NOLINT(readability-convert-member-functions-to-static)
{
#ifdef HAVE_IPCRYPT2
  switch (d_method) {
  case IPCryptMethod::pfx: {
    uint8_t ip16[16];
    struct sockaddr_storage sa;
    if (address.isIPv4()) {
      std::memcpy(&sa, &address.sin4, sizeof(sockaddr_in));
    }
    else {
      std::memcpy(&sa, &address.sin6, sizeof(sockaddr_in6));
    }
    ipcrypt_sockaddr_to_ip16(ip16, reinterpret_cast<sockaddr*>(&sa));
    ipcrypt_pfx_encrypt_ip16(d_ipcryptCtxPfx.get(), ip16);
    ipcrypt_ip16_to_sockaddr(&sa, ip16);
    if (address.isIPv4()) {
      return ComboAddress(reinterpret_cast<sockaddr_in*>(&sa));
    }
    else {
      return ComboAddress(reinterpret_cast<sockaddr_in6*>(&sa));
    }
  } break;
  default:
    throw std::runtime_error("Unsupported method");
    break;
  }
#else
  throw std::runtime_error("IPCrypt2 is not supported");
#endif
}
}
