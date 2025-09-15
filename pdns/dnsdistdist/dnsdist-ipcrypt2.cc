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

#include <stdexcept>

#include "dnsdist-ipcrypt2.hh"
#include "iputils.hh"

// XXX: IPCrypt2 does not have to be dnsdist-specific
namespace pdns::ipcrypt2 {
IPCrypt2::IPCrypt2(IPCryptMethod method, std::string &key) {
  d_method = method;
  switch (method) {
    case IPCryptMethod::pfx:
      if (key.size() != 32) {
        throw std::runtime_error("Key for IPCrypt PFX method is not 32 bytes");
      }
      d_ipcryptCtxPfx = new IPCryptPFX;
      ipcrypt_pfx_init(d_ipcryptCtxPfx, reinterpret_cast<const uint8_t*>(key.data()));
      break;
    default:
      // TODO: assert?
      throw std::runtime_error("Unsupported method");
      break;
  }
}

IPCrypt2::~IPCrypt2() {
  switch (d_method) {
    case IPCryptMethod::pfx:
      ipcrypt_pfx_deinit(d_ipcryptCtxPfx);
      break;
    default:
      return;
  }
};

ComboAddress IPCrypt2::encrypt(const ComboAddress &address) const {
  switch (d_method) {
    case IPCryptMethod::pfx:
      {
        std::string encryptedIP;
        encryptedIP.resize(IPCRYPT_MAX_IP_STR_BYTES);
        auto ret = ipcrypt_pfx_encrypt_ip_str(d_ipcryptCtxPfx, reinterpret_cast<char*>(&encryptedIP[0]), address.toString().c_str());
        // XXX: Do we *need* to resize?
        encryptedIP.resize(ret);
        return ComboAddress(encryptedIP);
      }
      break;
    default:
      throw std::runtime_error("Unsupported method");
      break;
  }
}
}
