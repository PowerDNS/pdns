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
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <unistd.h>
#include <libgen.h>
#include <errno.h>
#include "iputils.hh"
#include "pdnsexception.hh"

#include "namespaces.hh"

//! The DynMessenger can send messages to UNIX domain sockets and TCP sockets
class DynMessenger
{
  int d_s;

  struct sockaddr_un d_remote; // our remote address

  DynMessenger(const DynMessenger&); // NOT IMPLEMENTED

public:
  // CREATORS

  DynMessenger(const string& filename,
    int timeout_sec = 7,
    int timeout_usec = 0); //!< Create a DynMessenger sending to this file

  DynMessenger(const ComboAddress& remote,
    const string& password,
    int timeout_sec = 7,
    int timeout_usec = 0); //!< Create a DynMessenger sending to this file

  ~DynMessenger();

  // ACCESSORS
  int send(const string& message) const; //!< Send a message to a DynListener
  string receive() const; //!< receive an answer from a DynListener
};
