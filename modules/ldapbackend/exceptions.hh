/*
 *  PowerDNS LDAP Connector
 *  By PowerDNS.COM BV
 *  By Norbert Sendetzky <norbert@linuxnetworks.de> (2003-2007)
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#pragma once

#include <exception>
#include <stdexcept>
#include <string>

class LDAPException : public std::runtime_error
{
  public:
    explicit LDAPException( const std::string &str ) : std::runtime_error( str ) {}
};

class LDAPTimeout : public LDAPException
{
  public:
    explicit LDAPTimeout() : LDAPException( "Timeout" ) {}
};

class LDAPNoConnection : public LDAPException
{
  public:
    explicit LDAPNoConnection() : LDAPException( "No connection to LDAP server" ) {}
};

class LDAPNoSuchObject : public LDAPException
{
  public:
    explicit LDAPNoSuchObject() : LDAPException( "No such object" ) {}
};

