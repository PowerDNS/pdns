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
#ifndef PDNSEXCEPTION_HH
#define PDNSEXCEPTION_HH
/* (C) 2002 POWERDNS.COM BV */

#include<string>

#include "namespaces.hh"

//! Generic Exception thrown 
class PDNSException
{
public:
  PDNSException(){reason="Unspecified";};
  PDNSException(string r){reason=r;};
  
  string reason; //! Print this to tell the user what went wrong
};

class TimeoutException : public PDNSException
{
public:
  TimeoutException() : PDNSException() {}
  TimeoutException(string r) : PDNSException(r) {}
};

#endif
