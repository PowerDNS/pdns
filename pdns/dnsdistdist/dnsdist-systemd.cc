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
#include "config.h"
#include "dnsdist-systemd.hh"
#include <cstdlib>

bool running_in_service_mgr()
{
#ifdef HAVE_SYSTEMD
  char* c;
  c = getenv("NOTIFY_SOCKET"); // XXX Ideally we'd check for INVOCATION_ID (systemd.exec(5)), but that was introduced in systemd 232, and Debian Jessie has 215
  if (c != nullptr) {
    return true;
  }
#endif
  return false;
}
