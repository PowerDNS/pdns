/*
 *  PowerDNS LDAP Backend
 *  Copyright (C) 2011 Grégory Oestreicher <greg@kamago.net>
 *  Copyright (C) 2003-2007 Norbert Sendetzky <norbert@linuxnetworks.de>
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

#include <pdns/logger.hh>
#include "ldapauthenticator_p.hh"
#include "ldaputils.hh"

/*****************************
 * 
 * LdapSimpleAuthenticator
 * 
 ****************************/

LdapSimpleAuthenticator::LdapSimpleAuthenticator( const std::string& dn, const std::string& pw, int tmout )
	: binddn( dn ), bindpw( pw ), timeout( tmout )
{
}

bool LdapSimpleAuthenticator::authenticate( LDAP *conn )
{
	int msgid;

#ifdef HAVE_LDAP_SASL_BIND
	int rc;
	struct berval passwd;

	passwd.bv_val = (char *)bindpw.c_str();
	passwd.bv_len = strlen( passwd.bv_val );

	if( ( rc = ldap_sasl_bind( conn, binddn.c_str(), LDAP_SASL_SIMPLE, &passwd, NULL, NULL, &msgid ) ) != LDAP_SUCCESS )
	{
		fillLastError( conn, rc );
		return false;
	}
#else
	if( ( msgid = ldap_bind( conn, binddn.c_str(), bindpw.c_str(), LDAP_AUTH_SIMPLE ) ) == -1 )
	{
		fillLastError( conn, msgid );
		return false;
	}
#endif

	ldapWaitResult( conn, msgid, timeout, NULL );
	return true;
}

std::string LdapSimpleAuthenticator::getError() const
{
	return lastError;
}

void LdapSimpleAuthenticator::fillLastError( LDAP* conn, int code )
{
	lastError = ldapGetError( conn, code );
}
