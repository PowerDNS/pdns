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

#include "exceptions.hh"

#include <ldap.h>
#include <string>

void ldapSetOption( LDAP *conn, int option, void *value );

void ldapGetOption( LDAP *conn, int option, void *value );

std::string ldapGetError( LDAP *conn, int code );

int ldapWaitResult( LDAP *conn, int msgid, int timeout, LDAPMessage** result = NULL );

