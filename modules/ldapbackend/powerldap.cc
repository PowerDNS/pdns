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
  : d_msgid( msgid ), d_ld( ld ), d_finished( false ), d_status( -1 )
{
}


PowerLDAP::SearchResult::~SearchResult()
{
  if ( !d_finished )
    ldap_abandon_ext( d_ld, d_msgid, NULL, NULL ); // We don't really care about the return code as there's
                                                   // not much we can do now
}


bool PowerLDAP::SearchResult::finished() const
{
  return d_finished;
}


bool PowerLDAP::SearchResult::successful() const
{
  return d_status == LDAP_SUCCESS;
}


int PowerLDAP::SearchResult::status() const
{
  return d_status;
}


std::string PowerLDAP::SearchResult::error() const
{
  return d_error;
}


bool PowerLDAP::SearchResult::consumeAll()
{
  PowerLDAP::sentry_t r;
  while ( this->getNext( r ) )
    ;
  return this->finished();
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
        if ( result != NULL )
          ldap_msgfree( result );
        int err_code;
        ldapGetOption( d_ld, LDAP_OPT_ERROR_NUMBER, &err_code );
        if ( err_code == LDAP_SERVER_DOWN || err_code == LDAP_CONNECT_ERROR )
          throw LDAPNoConnection();
        else
          throw LDAPException( "Error waiting for LDAP result: " + ldapGetError( d_ld, err_code ) );
        break;
      case 0:
        if ( result != NULL )
          ldap_msgfree( result );
        result = NULL;
        throw LDAPTimeout();
        break;
      case LDAP_NO_SUCH_OBJECT:
        d_finished = true;
        ldap_msgfree( result );
        result = NULL;
        break;
      case LDAP_RES_SEARCH_REFERENCE:
        ldap_msgfree( result );
        result = NULL;
        break;
      case LDAP_RES_SEARCH_RESULT:
        d_finished = true;
        break;
      case LDAP_RES_SEARCH_ENTRY:
        // Yay!
        break;
      default:
        break;
    }

    if ( d_finished && result != NULL ) {
      int rc;
      char** referals;
      LDAPControl** controls = NULL;
      int prc = ldap_parse_result( d_ld, result, &rc, NULL, NULL, &referals, &controls, 0 );

      if ( referals != NULL )
        ldap_memvfree( (void**)referals );

      if ( prc != LDAP_SUCCESS ) {
        if ( controls != NULL )
          ldap_controls_free( controls );
        ldap_msgfree( result );
        d_status = prc;
        return false;
      }

      if ( rc != LDAP_SUCCESS ) {
        // Error found, that sucks
        d_status = rc;
        d_error = ldapGetError( d_ld, rc );

        // Try to see if we can gain any insight from the controls
        if ( controls != NULL ) {
          int idx = 0;
          LDAPControl* control;

          while ( controls[idx] != NULL ) {
            control = controls[idx];

            if ( strcmp( LDAP_CONTROL_SORTRESPONSE, control->ldctl_oid ) == 0 ) {
              ber_int_t rcode;
              prc = ldap_parse_sortresponse_control( d_ld, control, &rcode, NULL );
              if ( prc == LDAP_SUCCESS && rc != LDAP_SUCCESS ) {
                d_status = rc;
                d_error = "Sorting failed";
              }
            }
            ++idx;
          }
        }
      }
      else {
        d_status = 0;
      }

      if ( controls != NULL )
        ldap_controls_free( controls );

      ldap_msgfree( result );
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


PowerLDAP::PowerLDAP( const string& hosts, uint16_t port, bool tls )
{
  d_ld = 0;
  d_sort_supported = false;
  d_vlv_supported = false;
  d_hosts = hosts;
  d_port = port;
  d_tls = tls;
  ensureConnect();
}

void PowerLDAP::ensureConnect()
{
  int err;

  if(d_ld) {
    ldap_unbind_ext( d_ld, NULL, NULL );
    d_ld = 0;
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
        throw LDAPException( "Error initializing LDAP connection to '" + ldapuris );
    }
  }
#else
  if( ( d_ld = ldap_init( d_hosts.c_str(), d_port ) ) == NULL )
  {
    throw LDAPException( "Error initializing LDAP connection to '" + d_hosts + "'" );
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
    throw LDAPException( "Couldn't perform STARTTLS: " + std::string( ldap_err2string( err ) ) );
  }

  char* rootDseAttrs[] = { (char*)"supportedControl", NULL };
  LDAPMessage* result;
  err = ldap_search_ext_s( d_ld, "", LDAP_SCOPE_BASE, "objectClass=*", rootDseAttrs, 0, NULL, NULL, NULL, LDAP_NO_LIMIT, &result );
  if ( err != LDAP_SUCCESS ) {
    ldap_unbind_ext( d_ld, NULL, NULL );
    throw LDAPException( "Failed to search the root DSE for supported controls: " + std::string( ldap_err2string( err ) ) );
  }

  LDAPMessage* entry = ldap_first_entry( d_ld, result );
  berval** values;
  if ( entry != NULL && ( values = ldap_get_values_len( d_ld, entry, "supportedControl" ) ) != NULL ) {
    for ( int i = 0; values[i] != NULL; ++i ) {
      if ( strcmp( values[i]->bv_val, LDAP_CONTROL_SORTREQUEST ) == 0 )
        d_sort_supported = true;
      else if ( strcmp( values[i]->bv_val, LDAP_CONTROL_VLVREQUEST ) == 0 )
        d_vlv_supported = true;
    }
    ldap_value_free_len( values );
  }
  ldap_msgfree( result );
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


void PowerLDAP::bind( const string& ldapbinddn, const string& ldapsecret, int method, int timeout )
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

  ldapWaitResult( d_ld, msgid, timeout, NULL );
}


/**
 * Deprecated, use PowerLDAP::bind() instead
 */

void PowerLDAP::simpleBind( const string& ldapbinddn, const string& ldapsecret )
{
  this->bind( ldapbinddn, ldapsecret, LDAP_AUTH_SIMPLE, 30 );
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

  rc = ldap_search_ext( d_ld, base.c_str(), scope, filter.c_str(), const_cast<char**> (attr), 0, NULL, NULL, NULL, LDAP_NO_LIMIT, &msgid );
  if ( rc == LDAP_SERVER_DOWN || rc == LDAP_CONNECT_ERROR )
    throw LDAPNoConnection();
  else if ( rc != LDAP_SUCCESS )
    throw LDAPException( "Starting LDAP search: " + getError( rc ) );

  return SearchResult::Ptr( new SearchResult( msgid, d_ld ) );
}


PowerLDAP::SearchResult::Ptr PowerLDAP::sorted_search( const string& base, int scope, const string& filter, const string& sort, const char** attr, unsigned int limit )
{
  int msgid, rc, sort_rc;

  if ( !d_sort_supported )
    return SearchResult::Ptr();

  LDAPControl* sortcontrol;
  LDAPSortKey** sortkey;
  ldap_create_sort_keylist( &sortkey, const_cast<char*>( sort.c_str() ) );
  rc = ldap_create_sort_control( d_ld, sortkey, 1, &sortcontrol );
  if ( rc != LDAP_SUCCESS )
    throw LDAPException( "Failed to create sort control: " + getError( rc ) );
  ldap_free_sort_keylist( sortkey );

  LDAPControl* vlvcontrol = NULL;
  if ( d_vlv_supported && limit > 0 ) {
    LDAPVLVInfo virtuallist;
    virtuallist.ldvlv_version = 1;
    virtuallist.ldvlv_before_count = 0;
    virtuallist.ldvlv_after_count = limit;
    virtuallist.ldvlv_offset = 0;
    virtuallist.ldvlv_count = 1;
    ldap_create_vlv_control( d_ld, &virtuallist, &vlvcontrol );
  }

  LDAPControl* servercontrols[3];
  servercontrols[0] = sortcontrol;
  servercontrols[1] = vlvcontrol;
  servercontrols[2] = NULL;

  rc = ldap_search_ext( d_ld, base.c_str(), scope, filter.c_str(), const_cast<char**> (attr), 0, servercontrols, NULL, NULL, LDAP_NO_LIMIT, &msgid );
  if ( rc == LDAP_SERVER_DOWN || rc == LDAP_CONNECT_ERROR )
    throw LDAPNoConnection();
  else if ( rc != LDAP_SUCCESS )
    throw LDAPException( "Starting LDAP search: " + getError( rc ) );

  ldap_control_free( sortcontrol );
  if ( vlvcontrol != NULL )
    ldap_control_free( vlvcontrol );

  return SearchResult::Ptr( new SearchResult( msgid, d_ld ) );
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
      if( *i == '*' ||
          *i == '(' ||
          *i == ')' ||
          *i == '\\' ||
          *i == '\0' ||
          *i > 127)
      {
          sprintf(tmp,"\\%02x", (unsigned char)*i);

          a += tmp;
      }
      else
          a += *i;
  }

  return a;
}
