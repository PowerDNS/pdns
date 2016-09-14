/*
 *  PowerDNS LDAP Backend
 *  Copyright (C) 2011 Grégory Oestreicher <greg@kamago.net>
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

#include "ldapauthenticator.hh"

#ifndef LDAPAUTHENTICATOR_P_HH
#define LDAPAUTHENTICATOR_P_HH

class LdapSimpleAuthenticator : public LdapAuthenticator
{
	std::string binddn;
	std::string bindpw;
	int timeout;
	std::string lastError;

	void fillLastError( LDAP *conn, int code );

public:
	LdapSimpleAuthenticator( const std::string &dn, const std::string &pw, int timeout );
	virtual bool authenticate( LDAP *conn );
	virtual std::string getError() const;
};

#endif // LDAPAUTHENTICATOR_P_HH
