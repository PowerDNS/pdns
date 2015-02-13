/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002  PowerDNS.COM BV

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
#ifndef DYNMESSENGER_HH
#define DYNMESSENGER_HH

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

  DynMessenger(const DynMessenger &); // NOT IMPLEMENTED
  
public:
  // CREATORS

  DynMessenger(const string &filename,
    int timeout_sec = 7,
    int timeout_usec = 0);  //!< Create a DynMessenger sending to this file

  DynMessenger(const ComboAddress& remote,
    const string &password,
    int timeout_sec = 7,
    int timeout_usec = 0);  //!< Create a DynMessenger sending to this file

  ~DynMessenger();

  // ACCESSORS
  int send(const string &message) const; //!< Send a message to a DynListener
  string receive() const; //!< receive an answer from a DynListener
};
 
#endif
