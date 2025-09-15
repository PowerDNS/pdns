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
#include <string>

#include "dnsdist-ipcrypt2.hh"
#include "ipcrypt2.h"
#include "iputils.hh"

// ipcrypt2 namespace does not have to be dnsdist-specific
namespace pdns::ipcrypt2
{
IPCrypt2::IPCrypt2(const IPCryptMethod& method, const std::string& key) :
  d_method(method)
{
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
}

IPCrypt2::~IPCrypt2()
{
  switch (d_method) {
  case IPCryptMethod::pfx:
    if (d_ipcryptCtxPfx != nullptr) {
      ipcrypt_pfx_deinit(d_ipcryptCtxPfx.get());
    }
    break;
  default:
    return;
  }
};

ComboAddress IPCrypt2::encrypt(const ComboAddress& address) const
{
  switch (d_method) {
  case IPCryptMethod::pfx: {
    std::string encryptedIP;
    encryptedIP.resize(IPCRYPT_MAX_IP_STR_BYTES);
    auto ret = ipcrypt_pfx_encrypt_ip_str(d_ipcryptCtxPfx.get(), encryptedIP.data(), address.toString().c_str());
    // XXX: Do we *need* to resize?
    encryptedIP.resize(ret);
    return ComboAddress(encryptedIP);
  } break;
  default:
    throw std::runtime_error("Unsupported method");
    break;
  }
}
}
