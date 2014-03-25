/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002 - 2014  PowerDNS.COM BV

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
#ifndef SESSION_HH
#define SESSION_HH

#include <string>
#include <cerrno>

#include <sys/stat.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <strings.h>

#include "sstuff.hh"
#include "iputils.hh"
#include "mplexer.hh"
#include "syncres.hh"


//! The server class can be used to create listening servers
class Server
{
public:
  Server(const string &localaddress, int port) : d_local(localaddress.empty() ? "0.0.0.0" : localaddress, port), d_server_socket(InterNetwork, Stream, 0) {
    d_server_socket.setReuseAddr();
    d_server_socket.bind(d_local);
    d_server_socket.listen();
  }

  ComboAddress d_local;

  Socket *accept(); //!< Call accept() in an endless loop to accept new connections

protected:
  Socket d_server_socket;
};

#endif /* SESSION_HH */
