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
#include "exceptions.hh"
#include "ldapbackend.hh"
#include <cstdlib>


void LdapBackend::getUpdatedMasters( vector<DomainInfo>* domains )
{
  string filter;
  PowerLDAP::SearchResult::Ptr search;
  PowerLDAP::sentry_t result;
  const char* attronly[] = {
    "associatedDomain",
    NULL
  };

  try
  {
    // First get all domains on which we are master.
    filter = strbind( ":target:", "&(SOARecord=*)(PdnsDomainId=*)", getArg( "filter-axfr" ) );
    search = d_pldap->search( getArg( "basedn" ), LDAP_SCOPE_SUBTREE, filter, attronly );
  }
  catch( LDAPTimeout &lt )
  {
    g_log << Logger::Warning << d_myname << " Unable to search LDAP directory: " << lt.what() << endl;
    throw DBException( "LDAP server timeout" );
  }
  catch( LDAPNoConnection &lnc )
  {
    g_log << Logger::Warning << d_myname << " Connection to LDAP lost, trying to reconnect" << endl;
    if ( reconnect() )
      this->getUpdatedMasters( domains );
    else
      throw PDNSException( "Failed to reconnect to LDAP server" );
  }
  catch( LDAPException &le )
  {
    g_log << Logger::Error << d_myname << " Unable to search LDAP directory: " << le.what() << endl;
    throw PDNSException( "LDAP server unreachable" );   // try to reconnect to another server
  }
  catch( std::exception &e )
  {
    throw DBException( "STL exception" );
  }

  while( search->getNext( result ) ) {
    if( !result.count( "associatedDomain" ) || result["associatedDomain"].empty() )
      continue;

    DomainInfo di;
    if ( !getDomainInfo( DNSName( result["associatedDomain"][0] ), di ) )
      continue;

    if( di.notified_serial < di.serial )
      domains->push_back( di );
  }
}



void LdapBackend::setNotified( uint32_t id, uint32_t serial )
{
  string filter;
  PowerLDAP::SearchResult::Ptr search;
  PowerLDAP::sresult_t results;
  PowerLDAP::sentry_t entry;
  const char* attronly[] = { "associatedDomain", NULL };

  try
  {
    // Try to find the notified domain
    filter = strbind( ":target:", "PdnsDomainId=" + std::to_string( id ), getArg( "filter-axfr" ) );
    search = d_pldap->search( getArg( "basedn" ), LDAP_SCOPE_SUBTREE, filter, attronly );
    search->getAll( results, true );
  }
  catch( LDAPTimeout &lt )
  {
    g_log << Logger::Warning << d_myname << " Unable to search LDAP directory: " << lt.what() << endl;
    throw DBException( "LDAP server timeout" );
  }
  catch( LDAPNoConnection &lnc )
  {
    g_log << Logger::Warning << d_myname << " Connection to LDAP lost, trying to reconnect" << endl;
    if ( reconnect() )
      this->setNotified( id, serial );
    else
      throw PDNSException( "Failed to reconnect to LDAP server" );
  }
  catch( LDAPException &le )
  {
    g_log << Logger::Error << d_myname << " Unable to search LDAP directory: " << le.what() << endl;
    throw PDNSException( "LDAP server unreachable" );   // try to reconnect to another server
  }
  catch( std::exception &e )
  {
    throw DBException( "STL exception" );
  }

  if ( results.empty() )
    throw PDNSException( "No results found when trying to update domain notified_serial for ID " + std::to_string( id ) );

  entry = results.front();
  string dn = entry["dn"][0];
  string serialStr = std::to_string( serial );
  LDAPMod *mods[2];
  LDAPMod mod;
  char *vals[2];

  mod.mod_op = LDAP_MOD_REPLACE;
  mod.mod_type = (char*)"PdnsDomainNotifiedSerial";
  vals[0] = const_cast<char*>( serialStr.c_str() );
  vals[1] = NULL;
  mod.mod_values = vals;

  mods[0] = &mod;
  mods[1] = NULL;

  try
  {
    d_pldap->modify( dn, mods );
  }
  catch( LDAPNoConnection &lnc )
  {
    g_log << Logger::Warning << d_myname << " Connection to LDAP lost, trying to reconnect" << endl;
    if ( reconnect() )
      this->setNotified( id, serial );
    else
      throw PDNSException( "Failed to reconnect to LDAP server" );
  }
  catch( LDAPException &le )
  {
    g_log << Logger::Error << d_myname << " Unable to search LDAP directory: " << le.what() << endl;
    throw PDNSException( "LDAP server unreachable" );   // try to reconnect to another server
  }
  catch( std::exception &e )
  {
    throw DBException( "STL exception" );
  }
}
