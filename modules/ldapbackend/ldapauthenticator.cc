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

/*****************************
 * 
 * LdapGssapiAuthenticator
 * 
 ****************************/

static int ldapGssapiAuthenticatorSaslInteractCallback( LDAP *conn, unsigned flags, void *defaults, void *in )
{
  return LDAP_SUCCESS;
}

LdapGssapiAuthenticator::LdapGssapiAuthenticator( const std::string& kt, const std::string &ccache, int tmout )
  : logPrefix( "[LDAP GSSAPI] " ), keytabFile( kt ), cCacheFile( ccache ), timeout( tmout )
{
  krb5_error_code code;

  if ( ( code = krb5_init_context( &m_context ) ) != 0 )
    throw PDNSException( logPrefix + std::string( "Failed to initialize krb5 context" ) );

  // Locate the credentials cache file
  if ( !cCacheFile.empty() ) {
    std::string cCacheStr( "FILE:" + cCacheFile );
    code = krb5_cc_resolve( m_context, cCacheStr.c_str(), &m_ccache );
  }
  else {
    code = krb5_cc_default( m_context, &m_ccache );
  }

  if ( code != 0 )
    throw PDNSException( logPrefix +
                         std::string( "krb5 error when locating the credentials cache file: " ) +
                         std::string( krb5_get_error_message( m_context, code ) ) );
}

LdapGssapiAuthenticator::~LdapGssapiAuthenticator()
{
  krb5_free_context( m_context );
}

bool LdapGssapiAuthenticator::authenticate( LDAP *conn )
{
  int code = attemptAuth( conn );

  if ( code == -1 ) {
    return false;
  }
  else if ( code == -2 ) {
    // Here it may be possible to retry after obtainting a fresh ticket
    L<<Logger::Debug << logPrefix << "No TGT found, trying to acquire a new one" << std::endl;
    code = updateTgt();

    if ( attemptAuth( conn ) != 0 ) {
      L<<Logger::Error << logPrefix << "Failed to acquire a TGT" << std::endl;
      return false;
    }
  }

  return true;
}

std::string LdapGssapiAuthenticator::getError() const
{
  return lastError;
}

int LdapGssapiAuthenticator::attemptAuth( LDAP *conn )
{
  // Create SASL defaults
  SaslDefaults defaults;
  char *ldapOption = 0;

  ldap_get_option( conn, LDAP_OPT_X_SASL_MECH, ldapOption );
  if ( !ldapOption )
    defaults.mech = std::string( "GSSAPI" );
  else
    defaults.mech = std::string( ldapOption );
  ldap_memfree( ldapOption );

  ldap_get_option( conn, LDAP_OPT_X_SASL_REALM, ldapOption );
  if ( ldapOption )
    defaults.realm = std::string( ldapOption );
  ldap_memfree( ldapOption );

  ldap_get_option( conn, LDAP_OPT_X_SASL_AUTHCID, ldapOption );
  if ( ldapOption )
    defaults.authcid = std::string( ldapOption );
  ldap_memfree( ldapOption );

  ldap_get_option( conn, LDAP_OPT_X_SASL_AUTHZID, ldapOption );
  if ( ldapOption )
    defaults.authzid = std::string( ldapOption );
  ldap_memfree( ldapOption );

  // And now try to bind
  int rc = ldap_sasl_interactive_bind_s( conn, "", defaults.mech.c_str(),
                                         NULL, NULL, LDAP_SASL_QUIET,
                                         ldapGssapiAuthenticatorSaslInteractCallback, &defaults );
  L<<Logger::Debug << logPrefix << "ldap_sasl_interactive_bind_s returned " << rc << std::endl;

  if ( rc == LDAP_LOCAL_ERROR ) {
    // This may mean that the ticket has expired, so let the caller know
    lastError = ldapGetError( conn, rc );
    return -2;
  }
  else if ( rc != LDAP_SUCCESS ) {
    lastError = ldapGetError( conn, rc );
    return -1;
  }

  return rc;
}

int LdapGssapiAuthenticator::updateTgt()
{
  krb5_error_code code;
  krb5_creds credentials;
  krb5_keytab keytab;
  krb5_principal principal;
  krb5_get_init_creds_opt *options;

  if ( !keytabFile.empty() ) {
    std::string keytabStr( "FILE:" + keytabFile );
    code = krb5_kt_resolve( m_context, keytabStr.c_str(), &keytab );
  }
  else {
    code = krb5_kt_default( m_context, &keytab );
  }
  
  if ( code != 0 ) {
    L<<Logger::Error << logPrefix << "krb5 error when locating the keytab file: " << std::string( krb5_get_error_message( m_context, code ) ) << std::endl;
    return code;
  }

  // Extract the principal name from the keytab
  krb5_kt_cursor cursor;
  if ( ( code = krb5_kt_start_seq_get( m_context, keytab, &cursor ) ) != 0 ) {
    L<<Logger::Error << logPrefix << "krb5 error when initiating keytab search: " << std::string( krb5_get_error_message( m_context, code ) ) << std::endl;
    krb5_kt_close( m_context, keytab );
    return code;
  }

  krb5_keytab_entry entry;
  if ( ( code = krb5_kt_next_entry( m_context, keytab, &entry, &cursor ) ) == 0 ) {
    code = krb5_copy_principal( m_context, entry.principal, &principal );
    krb5_kt_free_entry( m_context, &entry );
  }

  krb5_kt_end_seq_get( m_context, keytab, &cursor );
  if ( code != 0 ) {
    L<<Logger::Error << logPrefix << "krb5 error when extracting principal information: " << std::string( krb5_get_error_message( m_context, code ) ) << std::endl;
    krb5_kt_close( m_context, keytab );
    krb5_free_principal( m_context, principal );
    return code;
  }

  if ( ( code = krb5_get_init_creds_opt_alloc( m_context, &options ) ) != 0 ) {
    L<<Logger::Error << logPrefix << "krb5 error when allocating credentials cache structure: " << std::string( krb5_get_error_message( m_context, code ) ) << std::endl;
    krb5_kt_close( m_context, keytab );
    krb5_free_principal( m_context, principal );
    return code;
  }
  krb5_get_init_creds_opt_set_default_flags( m_context, "pdns", krb5_principal_get_realm( m_context, principal ), options );

  // Get the ticket
  code = krb5_get_init_creds_keytab( m_context, &credentials, principal, keytab, 0, NULL, options );
  if ( code ) {
    L<<Logger::Error << logPrefix << "krb5 error when getting the TGT: " << std::string( krb5_get_error_message( m_context, code ) ) << std::endl;
    krb5_free_cred_contents( m_context, &credentials );
    krb5_kt_close( m_context, keytab );
    krb5_free_principal( m_context, principal );
    return code;
  }

  krb5_get_init_creds_opt_free( m_context, options );
  krb5_kt_close( m_context, keytab );

  // Use a temporary cache to get the initial credentials. This will be moved to the user-configured one later.
  krb5_ccache tmp_ccache = NULL;

  code = krb5_cc_new_unique( m_context, krb5_cc_get_type( m_context, m_ccache ), NULL, &tmp_ccache );
  if ( code ) {
    L<<Logger::Error<< logPrefix << "krb5 error when creating the temporary cache file: " << std::string( krb5_get_error_message( m_context, code ) ) << std::endl;
    krb5_kt_close( m_context, keytab );
    krb5_free_principal( m_context, principal );
    return code;
  }

  code = krb5_cc_initialize( m_context, tmp_ccache, principal );
  if ( code ) {
    L<<Logger::Error<< logPrefix << "krb5 error when initializing the temporary cache file: " << std::string( krb5_get_error_message( m_context, code ) ) << std::endl;
    krb5_free_cred_contents( m_context, &credentials );
    krb5_free_principal( m_context, principal );
    return code;
  }

  code = krb5_cc_store_cred( m_context, tmp_ccache, &credentials );
  if ( code ) {
    L<<Logger::Error << logPrefix << "krb5 error when storing the ticket in the credentials cache: " << std::string( krb5_get_error_message( m_context, code ) ) << std::endl;
    krb5_cc_close( m_context, tmp_ccache );
    krb5_free_cred_contents( m_context, &credentials );
    krb5_free_principal( m_context, principal );
    return code;
  }

  code = krb5_cc_move( m_context, tmp_ccache, m_ccache );
  if ( code ) {
    L<<Logger::Error << logPrefix << "krb5 error when moving the credentials cache: " << std::string( krb5_get_error_message( m_context, code ) ) << std::endl;
    krb5_free_cred_contents( m_context, &credentials );
    krb5_free_principal( m_context, principal );
    return code;
  }

  krb5_cc_close( m_context, tmp_ccache );
  krb5_free_cred_contents( m_context, &credentials );
  krb5_free_principal( m_context, principal );

  L<<Logger::Debug << logPrefix << "done getting TGT, will return " << code << std::endl;
  return code;
}
