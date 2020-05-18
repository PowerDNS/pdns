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

#include "iputils.hh"

namespace pdns {
  /*! pick a random query local address for family
   *
   * Will always return a ComboAddress.
   *
   * @param family Address Family, only AF_INET and AF_INET6 are supported
   * @param port   Port to set in the returned ComboAddress
   */
  ComboAddress getQueryLocalAddress(const sa_family_t family, const in_port_t port);

  /*! Returns a non-Any address QLA, or an empty QLA when the QLA is any
   *
   * @param family  Address Family
   */
  ComboAddress getNonAnyQueryLocalAddress(const sa_family_t family);

  /*! Populate the query local address vectors
   *
   * Will throw when an address can't be parsed
   *
   * @param qla  A string of one or more ip addresses, separated by
   *             spaces, semi-colons or commas
   */
  void parseQueryLocalAddress(const std::string &qla);

  /*! Is the address family explicitly enabled
   *
   * i.e. was there an address parsed by parseQueryLocalAddress belonging
   * to this family
   *
   * @param family  Address Family, only AF_INET and AF_INET6 are supported
   */
  bool isQueryLocalAddressFamilyEnabled(const sa_family_t family);
} // namespace pdns
