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

#include <krb5.h>
#include "ldapauthenticator.hh"

#ifndef LDAPAUTHENTICATOR_P_HH
#define LDAPAUTHENTICATOR_P_HH

#ifndef HAVE_KRB5_GET_INIT_CREDS_OPT_SET_DEFAULT_FLAGS
#define krb5_get_init_creds_opt_set_default_flags( a, b, c, d ) /* This does not exist with MIT Kerberos */
#endif

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

class LdapGssapiAuthenticator : public LdapAuthenticator
{
    std::string logPrefix;
    std::string keytabFile;
    std::string cCacheFile;
    int timeout;
    std::string lastError;

    krb5_context m_context;
    krb5_ccache m_ccache;
    
    struct SaslDefaults {
      std::string mech;
      std::string realm;
      std::string authcid;
      std::string authzid;
    };
  
    int attemptAuth( LDAP *conn );
    int updateTgt();
  
  public:
    LdapGssapiAuthenticator( const std::string &keytab, const std::string &credsCache, int timeout );
    ~LdapGssapiAuthenticator();
    virtual bool authenticate( LDAP *conn );
    virtual std::string getError() const;
};

#endif // LDAPAUTHENTICATOR_P_HH
