/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002 - 2016 PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2
    as published by the Free Software Foundation

    Additionally, the license of this program contains a special
    exception which allows to distribute the program in binary form when
    it is linked against OpenSSL.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

#pragma once

static const char*rootIps4[]={"198.41.0.4",             // a.root-servers.net.
                              "192.228.79.201",         // b.root-servers.net.
                              "192.33.4.12",            // c.root-servers.net.
                              "199.7.91.13",            // d.root-servers.net.
                              "192.203.230.10",         // e.root-servers.net.
                              "192.5.5.241",            // f.root-servers.net.
                              "192.112.36.4",           // g.root-servers.net.
                              "198.97.190.53",          // h.root-servers.net.
                              "192.36.148.17",          // i.root-servers.net.
                              "192.58.128.30",          // j.root-servers.net.
                              "193.0.14.129",           // k.root-servers.net.
                              "199.7.83.42",            // l.root-servers.net.
                              "202.12.27.33"            // m.root-servers.net.
                              };

static const char*rootIps6[]={"2001:503:ba3e::2:30",    // a.root-servers.net.
                              "2001:500:84::b",         // b.root-servers.net.
                              "2001:500:2::c",          // c.root-servers.net.
                              "2001:500:2d::d",         // d.root-servers.net.
                              NULL,                     // e.root-servers.net.
                              "2001:500:2f::f",         // f.root-servers.net.
                              NULL,                     // g.root-servers.net.
                              "2001:500:1::53",         // h.root-servers.net.
                              "2001:7fe::53",           // i.root-servers.net.
                              "2001:503:c27::2:30",     // j.root-servers.net.
                              "2001:7fd::1",            // k.root-servers.net.
                              "2001:500:9f::42",        // l.root-servers.net.
                              "2001:dc3::35"            // m.root-servers.net.
                              };
