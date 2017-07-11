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
#ifndef PDNS_LUA_AUTH_HH
#define PDNS_LUA_AUTH_HH
#include "dns.hh"
#include "iputils.hh"
#include "dnspacket.hh"
#include "lua-pdns.hh"
#include "lock.hh"

class AuthLua : public PowerDNSLua
{
public:
  explicit AuthLua(const std::string& fname);
  // ~AuthLua();
  DNSPacket* prequery(DNSPacket *p);

private:
  void registerLuaDNSPacket(void);

  pthread_mutex_t d_lock;
};

#endif
