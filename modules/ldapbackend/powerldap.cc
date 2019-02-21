/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 * originally authored by Norbert Sendetzky
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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "exceptions.hh"
#include "ldapauthenticator.hh"
#include "ldaputils.hh"
#include "powerldap.hh"
#include "pdns/misc.hh"
#include <sys/time.h>


PowerLDAP::SearchResult::SearchResult( int msgid, LDAP* ld )
  : d_ld( ld ), d_msgid( msgid ), d_finished( false )
{
}


PowerLDAP::SearchResult::~SearchResult()
{
  if ( !d_finished )
    ldap_abandon_ext( d_ld, d_msgid, NULL, NULL ); // We don't really care about the return code as there's
                                                   // not much we can do now
}


bool PowerLDAP::SearchResult::getNext( PowerLDAP::sentry_t& entry, bool dn, int timeout )
{
  int i;
  char* attr;
  BerElement* ber;
  struct berval** berval;
  vector<string> values;
  LDAPMessage* result = NULL;
  LDAPMessage* object;

  while ( !d_finished && result == NULL ) {
    i = ldapWaitResult( d_ld, d_msgid, 5, &result );
    switch ( i ) {
      case -1:
        int err_code;
        ldapGetOption( d_ld, LDAP_OPT_ERROR_NUMBER, &err_code );
        if ( err_code == LDAP_SERVER_DOWN || err_code == LDAP_CONNECT_ERROR )
          throw LDAPNoConnection();
        else
          throw LDAPException( "Error waiting for LDAP result: " + ldapGetError( d_ld, err_code ) );
        break;
      case 0:
        throw LDAPTimeout();
        break;
      case LDAP_NO_SUCH_OBJECT:
        return false;
      case LDAP_RES_SEARCH_REFERENCE:
        ldap_msgfree( result );
        result = NULL;
        break;
      case LDAP_RES_SEARCH_RESULT:
        d_finished = true;
        ldap_msgfree( result );
        break;
      case LDAP_RES_SEARCH_ENTRY:
        // Yay!
        break;
    }
  }

  if ( d_finished )
    return false;

  if( ( object = ldap_first_entry( d_ld, result ) ) == NULL )
  {
    ldap_msgfree( result );
    throw LDAPException( "Couldn't get first result entry: " + ldapGetError( d_ld, -1 ) );
  }

  entry.clear();

  if( dn )
  {
    attr = ldap_get_dn( d_ld, object );
    values.push_back( string( attr ) );
    ldap_memfree( attr );
    entry["dn"] = values;
  }

  if( ( attr = ldap_first_attribute( d_ld, object, &ber ) ) != NULL )
  {
    do
    {
      if( ( berval = ldap_get_values_len( d_ld, object, attr ) ) != NULL )
      {
        values.clear();
        for( i = 0; i < ldap_count_values_len( berval ); i++ )
        {
          values.push_back( berval[i]->bv_val );   // use berval[i]->bv_len for non string values?
        }

        entry[attr] = values;
        ldap_value_free_len( berval );
      }
      ldap_memfree( attr );
    }
    while( ( attr = ldap_next_attribute( d_ld, object, ber ) ) != NULL );

    ber_free( ber, 0 );
  }

  ldap_msgfree( result );
  return true;
}


void PowerLDAP::SearchResult::getAll( PowerLDAP::sresult_t& results, bool dn, int timeout )
{
  PowerLDAP::sentry_t entry;

  while( getNext( entry, dn, timeout ) )
  {
    results.push_back( entry );
  }
}


PowerLDAP::PowerLDAP( const string& hosts, uint16_t port, bool tls, int timeout )
{
  d_ld = 0;
  d_hosts = hosts;
  d_port = port;
  d_tls = tls;
  d_timeout = timeout;
  ensureConnect();
}

void PowerLDAP::ensureConnect()
{
  int err;

  if(d_ld) {
    ldap_unbind_ext( d_ld, NULL, NULL );
  }

#ifdef HAVE_LDAP_INITIALIZE
  if( ( err = ldap_initialize( &d_ld, d_hosts.c_str() ) ) != LDAP_SUCCESS )
  {
    string ldapuris;
    vector<string> uris;
    stringtok( uris, d_hosts );

    for( size_t i = 0; i < uris.size(); i++ )
    {
      ldapuris += " ldap://" + uris[i];
    }

    if( ( err = ldap_initialize( &d_ld, ldapuris.c_str() ) ) != LDAP_SUCCESS )
    {
        throw LDAPException( "Error initializing LDAP connection to '" + ldapuris + ": " + getError( err ) );
    }
  }
#else
  if( ( d_ld = ldap_init( d_hosts.c_str(), d_port ) ) == NULL )
  {
    throw LDAPException( "Error initializing LDAP connection to '" + d_hosts + "': " + string( strerror( errno ) ) );
  }
#endif

  int protocol = LDAP_VERSION3;
  if( ldap_set_option( d_ld, LDAP_OPT_PROTOCOL_VERSION, &protocol ) != LDAP_OPT_SUCCESS )
  {
    protocol = LDAP_VERSION2;
    if( ldap_set_option( d_ld, LDAP_OPT_PROTOCOL_VERSION, &protocol ) != LDAP_OPT_SUCCESS )
    {
      ldap_unbind_ext( d_ld, NULL, NULL );
      throw LDAPException( "Couldn't set protocol version to LDAPv3 or LDAPv2" );
    }
  }

  if( d_tls && ( err = ldap_start_tls_s( d_ld, NULL, NULL ) ) != LDAP_SUCCESS )
  {
    ldap_unbind_ext( d_ld, NULL, NULL );
    throw LDAPException( "Couldn't perform STARTTLS: " + getError( err ) );
  }
}


PowerLDAP::~PowerLDAP()
{
  ldap_unbind_ext( d_ld, NULL, NULL );
}


bool PowerLDAP::connect()
{
  try
  {
    ensureConnect();
    return true;
  }
  catch( LDAPException &le )
  {
    return false;
  }
}


void PowerLDAP::setOption( int option, int value )
{
  ldapSetOption( d_ld, option, (void*) &value );
}


void PowerLDAP::getOption( int option, int *value )
{
  ldapGetOption( d_ld, option, (void*) value );
}


void PowerLDAP::bind( LdapAuthenticator* authenticator )
{
  if ( !authenticator->authenticate( d_ld ) )
    throw LDAPException( "Failed to bind to LDAP server: " + authenticator->getError() );
}


void PowerLDAP::bind( const string& ldapbinddn, const string& ldapsecret, int method)
{
  int msgid;

#ifdef HAVE_LDAP_SASL_BIND
  int rc;
  struct berval passwd;

  passwd.bv_val = (char *)ldapsecret.c_str();
  passwd.bv_len = strlen( passwd.bv_val );

  if( ( rc = ldap_sasl_bind( d_ld, ldapbinddn.c_str(), LDAP_SASL_SIMPLE, &passwd, NULL, NULL, &msgid ) ) != LDAP_SUCCESS )
  {
    throw LDAPException( "Failed to bind to LDAP server: " + getError( rc ) );
  }
#else
  if( ( msgid = ldap_bind( d_ld, ldapbinddn.c_str(), ldapsecret.c_str(), method ) ) == -1 )
  {
    throw LDAPException( "Failed to bind to LDAP server: " + getError( msgid ) );
  }
#endif

  ldapWaitResult( d_ld, msgid, d_timeout, NULL );
}


/**
 * Deprecated, use PowerLDAP::bind() instead
 */

void PowerLDAP::simpleBind( const string& ldapbinddn, const string& ldapsecret )
{
  this->bind( ldapbinddn, ldapsecret, LDAP_AUTH_SIMPLE );
}


void PowerLDAP::add( const string &dn, LDAPMod *mods[] )
{
  int rc;

  rc = ldap_add_ext_s( d_ld, dn.c_str(), mods, NULL, NULL );
  if ( rc == LDAP_SERVER_DOWN || rc == LDAP_CONNECT_ERROR )
    throw LDAPNoConnection();
  else if ( rc != LDAP_SUCCESS )
    throw LDAPException( "Error adding LDAP entry " + dn + ": " + getError( rc ) );
}


void PowerLDAP::modify( const string &dn, LDAPMod *mods[], LDAPControl **scontrols, LDAPControl **ccontrols )
{
  int rc;

  rc = ldap_modify_ext_s( d_ld, dn.c_str(), mods, scontrols, ccontrols );
  if ( rc == LDAP_SERVER_DOWN || rc == LDAP_CONNECT_ERROR )
    throw LDAPNoConnection();
  else if ( rc != LDAP_SUCCESS )
    throw LDAPException( "Error modifying LDAP entry " + dn + ": " + getError( rc ) );
}


void PowerLDAP::del( const string& dn )
{
  int rc;

  rc = ldap_delete_ext_s( d_ld, dn.c_str(), NULL, NULL );
  if ( rc == LDAP_SERVER_DOWN || rc == LDAP_CONNECT_ERROR )
    throw LDAPNoConnection();
  else if ( rc != LDAP_SUCCESS && rc != LDAP_NO_SUCH_OBJECT )
    throw LDAPException( "Error deleting LDAP entry " + dn + ": " + getError( rc ) );
}


PowerLDAP::SearchResult::Ptr PowerLDAP::search( const string& base, int scope, const string& filter, const char** attr )
{
  int msgid, rc;

  if ( ( rc = ldap_search_ext( d_ld, base.c_str(), scope, filter.c_str(), const_cast<char**> (attr), 0, NULL, NULL, NULL, LDAP_NO_LIMIT, &msgid ) ) ) {
    throw LDAPException( "Starting LDAP search: " + getError( rc ) );
  }

  return SearchResult::Ptr( new SearchResult( msgid, d_ld ) );
}


/**
 * Function waits for a result, returns its type and optionally stores the result.
 * If the result is returned, the caller is responsible for freeing it with
 * ldap_msgfree!
 */

int PowerLDAP::waitResult( int msgid, LDAPMessage** result )
{
  return ldapWaitResult( d_ld, msgid, d_timeout, result );
}


bool PowerLDAP::getSearchEntry( int msgid, sentry_t& entry, bool dn )
{
  int i;
  char* attr;
  BerElement* ber;
  struct berval** berval;
  vector<string> values;
  LDAPMessage* result;
  LDAPMessage* object;
  bool hasResult = false;

  while ( !hasResult ) {
    i = waitResult( msgid, &result );
    // Here we deliberately ignore LDAP_RES_SEARCH_REFERENCE as we don't follow them.
    // Instead we get the next result.
    // If the function returned an error (i <= 0) we'll deal with after this loop too.
    if ( i == LDAP_RES_SEARCH_ENTRY || i == LDAP_RES_SEARCH_RESULT || i <= 0 )
      hasResult = true;
  }

  if ( i == -1 ) {
    // Error while retrieving the message
    int err_code;
    ldapGetOption( d_ld, LDAP_OPT_ERROR_NUMBER, &err_code );
    if ( err_code == LDAP_SERVER_DOWN || err_code == LDAP_CONNECT_ERROR )
      throw LDAPNoConnection();
    else
      throw LDAPException( "PowerLDAP::getSearchEntry(): Error when retrieving LDAP result: " + getError( err_code ) );
  }

  if ( i == 0 ) {
    // Timeout expired before the message could be retrieved
    throw LDAPTimeout();
  }

  if ( i == LDAP_RES_SEARCH_RESULT ) {
    // We're done with this request
    ldap_msgfree( result );
    return false;
  }

  if( ( object = ldap_first_entry( d_ld, result ) ) == NULL )
  {
    ldap_msgfree( result );
    throw LDAPException( "Couldn't get first result entry: " + getError() );
  }

  entry.clear();

  if( dn )
  {
    attr = ldap_get_dn( d_ld, object );
    values.push_back( string( attr ) );
    ldap_memfree( attr );
    entry["dn"] = values;
  }

  if( ( attr = ldap_first_attribute( d_ld, object, &ber ) ) != NULL )
  {
    do
    {
      if( ( berval = ldap_get_values_len( d_ld, object, attr ) ) != NULL )
      {
        values.clear();
        for( i = 0; i < ldap_count_values_len( berval ); i++ )
        {
          values.push_back( berval[i]->bv_val );   // use berval[i]->bv_len for non string values?
        }

        entry[attr] = values;
        ldap_value_free_len( berval );
      }
      ldap_memfree( attr );
    }
    while( ( attr = ldap_next_attribute( d_ld, object, ber ) ) != NULL );

    ber_free( ber, 0 );
  }

  ldap_msgfree( result );
  return true;
}


void PowerLDAP::getSearchResults( int msgid, sresult_t& result, bool dn )
{
  sentry_t entry;

  result.clear();
  while( getSearchEntry( msgid, entry, dn ) )
  {
    result.push_back( entry );
  }
}


const string PowerLDAP::getError( int rc )
{
  return ldapGetError( d_ld, rc );
}


const string PowerLDAP::escape( const string& str )
{
  string a;
  string::const_iterator i;
  char tmp[4];

  for( i = str.begin(); i != str.end(); i++ )
  {
      // RFC4515 3
      if( (unsigned char)*i == '*' ||
          (unsigned char)*i == '(' ||
          (unsigned char)*i == ')' ||
          (unsigned char)*i == '\\' ||
          (unsigned char)*i == '\0' ||
          (unsigned char)*i > 127)
      {
          snprintf(tmp, sizeof(tmp), "\\%02x", (unsigned char)*i);

          a += tmp;
      }
      else
          a += *i;
  }

  return a;
}
