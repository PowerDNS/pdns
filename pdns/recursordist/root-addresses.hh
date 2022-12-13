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

static const char* const rootIps4[] = {
  "198.41.0.4", // a.root-servers.net.
  "199.9.14.201", // b.root-servers.net.
  "192.33.4.12", // c.root-servers.net.
  "199.7.91.13", // d.root-servers.net.
  "192.203.230.10", // e.root-servers.net.
  "192.5.5.241", // f.root-servers.net.
  "192.112.36.4", // g.root-servers.net.
  "198.97.190.53", // h.root-servers.net.
  "192.36.148.17", // i.root-servers.net.
  "192.58.128.30", // j.root-servers.net.
  "193.0.14.129", // k.root-servers.net.
  "199.7.83.42", // l.root-servers.net.
  "202.12.27.33" // m.root-servers.net.
};
static size_t const rootIps4Count = sizeof(rootIps4) / sizeof(*rootIps4);

static const char* const rootIps6[] = {
  "2001:503:ba3e::2:30", // a.root-servers.net.
  "2001:500:200::b", // b.root-servers.net.
  "2001:500:2::c", // c.root-servers.net.
  "2001:500:2d::d", // d.root-servers.net.
  "2001:500:a8::e", // e.root-servers.net.
  "2001:500:2f::f", // f.root-servers.net.
  "2001:500:12::d0d", // g.root-servers.net.
  "2001:500:1::53", // h.root-servers.net.
  "2001:7fe::53", // i.root-servers.net.
  "2001:503:c27::2:30", // j.root-servers.net.
  "2001:7fd::1", // k.root-servers.net.
  "2001:500:9f::42", // l.root-servers.net.
  "2001:dc3::35" // m.root-servers.net.
};
static size_t const rootIps6Count = sizeof(rootIps6) / sizeof(*rootIps6);
