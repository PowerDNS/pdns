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

#include "tcpiohandler.hh"

class TLSSessionCache
{
public:
  TLSSessionCache()
  {
  }
  void cleanup(time_t now);

  void putSession(const ComboAddress& remote, std::unique_ptr<TLSSession>&& session);
  std::unique_ptr<TLSSession> getSession(const ComboAddress& remote, time_t now);

private:
  struct Entry
  {
    // might become a FIFO at some point
    std::unique_ptr<TLSSession> d_session{nullptr};
    time_t d_lastUse{0};
  };

  std::map<ComboAddress, Entry> d_sessions;
  std::mutex d_lock;
};

extern TLSSessionCache g_sessionCache;
