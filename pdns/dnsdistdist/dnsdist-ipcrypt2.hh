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

#include <string>

#include "ipcrypt2.h"
#include "iputils.hh"

namespace pdns::ipcrypt2 {

enum IPCryptMethod {
  deterministic,
  pfx,
  nd,
  ndx
};

class IPCrypt2 {
public:
  IPCrypt2(IPCryptMethod method, std::string &key);
  ~IPCrypt2();

  ComboAddress encrypt(const ComboAddress& address) const;
private:
  IPCryptMethod d_method;
  // XXX: unique_ptr? We could have a context for each method
  struct IPCryptPFX *d_ipcryptCtxPfx;
};
}
