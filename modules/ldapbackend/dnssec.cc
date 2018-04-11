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
 
 
bool LdapBackend::doesDNSSEC()
{
  return d_dnssec;
}


std::string LdapBackend::getDomainMetadataDN( const DNSName &name )
{
  std::string dn;
  std::string filter = strbind( ":domain:", d_pldap->escape( name.toStringRootDot() ), getArg( "metadata-searchfilter" ) );
  const char* attributes[] = { "objectClass", NULL };
  PowerLDAP::sentry_t result;

  try {
    PowerLDAP::SearchResult::Ptr search = d_pldap->search( d_metadata_searchdn, LDAP_SCOPE_SUBTREE, filter, attributes );

    if ( search->getNext( result, true ) ) {
      if ( result.count( "dn" ) && !result["dn"].empty() )
        dn = result["dn"][0];
    }

    g_log<<Logger::Debug<< d_myname << " getDomainMetadataDN will return " << dn << endl;
    return dn;
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
      return this->getDomainMetadataDN( name );
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
    g_log << Logger::Error << d_myname << " Caught STL exception searching for domain " << name << " under the metadata DN: " << e.what() << endl;
    throw DBException( "STL exception" );
  }
}


bool LdapBackend::getDomainMetadata( const DNSName& name, const std::string& kind, std::vector<std::string>& meta )
{
  g_log<<Logger::Debug<< d_myname << " Getting metadata " << kind << " for domain " << name << endl;

  if ( !d_dnssec && isDnssecDomainMetadata( kind ) )
    return false;

  std::string basedn = this->getDomainMetadataDN( name );
  if ( basedn.empty() )
    return false;
  std::string filter = "(&(objectClass=PdnsMetadata)(cn=" + d_pldap->escape( kind ) + "))";
  const char* attributes[] = { "PdnsMetadataValue", NULL };
  PowerLDAP::sentry_t result;

  try {
    PowerLDAP::SearchResult::Ptr search = d_pldap->search( basedn, LDAP_SCOPE_SUBTREE, filter, attributes );

    // We're supposed to get just one entry
    if ( search->getNext( result, d_getdn ) ) {
      if ( result.count( "PdnsMetadataValue" ) && !result["PdnsMetadataValue"].empty() ) {
        for ( const auto& value : result["PdnsMetadataValue"] )
          meta.push_back( value );
      }
    }

    return true;
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
      return this->getDomainMetadata( name, kind, meta );
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
    g_log << Logger::Error << d_myname << " Caught STL exception retrieving metadata for domain " << name << ": " << e.what() << endl;
    throw DBException( "STL exception" );
  }
}

bool LdapBackend::getAllDomainMetadata( const DNSName& name, std::map<std::string, std::vector<std::string> >& meta )
{
  g_log<<Logger::Debug<< d_myname << " Getting all metadata for domain " << name << endl;

  std::string basedn = this->getDomainMetadataDN( name );
  if ( basedn.empty() )
    return false;

  std::string filter = "objectClass=PdnsMetadata";
  const char* attributes[] = { "cn", "PdnsMetadataValue", NULL };
  PowerLDAP::sentry_t result;

  try {
    PowerLDAP::SearchResult::Ptr search = d_pldap->search( basedn, LDAP_SCOPE_SUBTREE, filter, attributes );
    meta.clear();

    while ( search->getNext( result, false ) ) {
      meta[ result["cn"][0] ] = result["PdnsMetadataValue"];
    }

    return true;
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
      return this->getAllDomainMetadata( name, meta );
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
    g_log << Logger::Error << d_myname << " Caught STL exception retrieving metadata for all domains" << endl;
    throw DBException( "STL exception" );
  }
}

bool LdapBackend::setDomainMetadata( const DNSName& name, const std::string& kind, const std::vector<std::string>& meta )
{
  g_log<<Logger::Debug<< d_myname << " Setting metadata " << kind << " for domain " << name << endl;

  if ( !d_dnssec && isDnssecDomainMetadata( kind ) )
    return false;

  // We won't create the root entry here as this is left to the discretion of the LDAP admin,
  // so just bail out. Maybe throw an exception?
  std::string basedn = this->getDomainMetadataDN( name );
  if ( basedn.empty() )
    return false;

  try {
    bool ret = false;
    std::string filter = "(&(objectClass=PdnsMetadata)(cn=" + d_pldap->escape( kind ) + "))";
    const char* attributes[] = { "cn", NULL };
    PowerLDAP::sentry_t result;

    PowerLDAP::SearchResult::Ptr search = d_pldap->search( basedn, LDAP_SCOPE_SUBTREE, filter, attributes );
    bool exists = search->getNext( result, true );

    if ( !exists ) {
      // OK, this metadata entry doesn't exist. Let's just create it, yay!
      if ( !meta.empty() ) {
        g_log<<Logger::Debug<< d_myname << " Creating metadata " << kind << " for domain " << name << endl;

        std::string escaped_kind = d_pldap->escape( kind );
        std::string dn = "cn=" + escaped_kind + "," + basedn;

        std::vector<char*> vals( meta.size() + 1 );
        for ( int i = 0; i < meta.size(); ++i )
          vals[i] = (char*)( meta.at( i ).c_str() );
        vals[meta.size()] = NULL;

        LDAPMod objectClassMod;
        objectClassMod.mod_op = LDAP_MOD_ADD;
        objectClassMod.mod_type = (char*)"objectClass";
        char* objectClassValues[] = { (char*)"top", (char*)"PdnsMetadata", NULL };
        objectClassMod.mod_values = objectClassValues;

        LDAPMod cnMod;
        cnMod.mod_op = LDAP_MOD_ADD;
        cnMod.mod_type = (char*)"cn";
        char* cnValues[] = { (char*)( escaped_kind.c_str() ), NULL };
        cnMod.mod_values = cnValues;

        LDAPMod valueMod;
        valueMod.mod_op = LDAP_MOD_ADD;
        valueMod.mod_type = (char*)"PdnsMetadataValue";
        valueMod.mod_values = vals.data();

        LDAPMod* mods[4];
        mods[0] = &objectClassMod;
        mods[1] = &cnMod;
        mods[2] = &valueMod;
        mods[3] = NULL;

        d_pldap->add( dn, mods );
      }
      ret = true;
    }
    else {
      if ( meta.empty() ) {
        g_log<<Logger::Debug<< d_myname << " Deleting metadata " << kind << " for domain " << name << endl;
        d_pldap->del( result["dn"][0] );
      }
      else {
        g_log<<Logger::Debug<< d_myname << " Replacing metadata " << kind << " for domain " << name << endl;

        std::vector<char*> vals( meta.size() + 1 );
        for ( int i = 0; i < meta.size(); ++i )
          vals[i] = (char*)( meta.at( i ).c_str() );
        vals[meta.size()] = NULL;

        LDAPMod mod;
        mod.mod_op = LDAP_MOD_REPLACE;
        mod.mod_type = (char*)"PdnsMetadataValue";
        mod.mod_values = vals.data();

        LDAPMod* mods[2];
        mods[0] = &mod;
        mods[1] = NULL;

        d_pldap->modify( result["dn"][0], mods );
      }
      ret = true;
    }

    return ret;
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
      return this->setDomainMetadata( name, kind, meta );
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
    g_log << Logger::Error << d_myname << " Caught STL exception setting metadata for domain " << name << ": " << e.what() << endl;
    throw DBException( "STL exception" );
  }
}


bool LdapBackend::getDomainKeys( const DNSName& name, std::vector<KeyData>& keys )
{
  if ( !d_dnssec )
    return false;

  std::string basedn = this->getDomainMetadataDN( name );
  if ( basedn.empty() )
    return false;

  g_log<<Logger::Debug<< d_myname << " Retrieving zone keys for " << name << std::endl;

  try {
    PowerLDAP::sentry_t result;
    std::string filter = "objectClass=PdnsDomainKey";
    const char* attributes[] = {
      "PdnsKeyId",
      "PdnsKeyFlags",
      "PdnsKeyContent",
      "PdnsKeyActive",
      NULL
    };

    PowerLDAP::SearchResult::Ptr search = d_pldap->search( basedn, LDAP_SCOPE_SUBTREE, filter, attributes );

    while ( search->getNext( result, false ) ) {
      KeyData kd;
      kd.id = pdns_stou( result["PdnsKeyId"][0] );
      kd.flags = pdns_stou( result["PdnsKeyFlags"][0] );
      kd.content = result["PdnsKeyContent"][0];
      if ( result.count( "PdnsKeyActive" ) )
        kd.active = true;
      else
        kd.active = false;

      g_log<<Logger::Debug<< d_myname << " Found key with ID " << kd.id << std::endl;
      keys.push_back( kd );
    }

    return true;
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
      return this->getDomainKeys( name, keys );
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
    g_log << Logger::Error << d_myname << " Caught STL exception retrieving key for domain " << name << ": " << e.what() << endl;
    throw DBException( "STL exception" );
  }
}


bool LdapBackend::addDomainKey( const DNSName& name, const KeyData& key, int64_t& id )
{
  if ( !d_dnssec )
    return false;

  g_log<<Logger::Debug<< d_myname << " Adding domain key for " << name << std::endl;

  // Same as in setDomainMetadata, we don't create the required entries
  std::string basedn = this->getDomainMetadataDN( name );
  if ( basedn.empty() )
    return false;

  try {
    // Prepare all the elements first. As LDAP doesn't have the concept of transaction
    // we risk ending up with two keys with the same ID if there are insertions between
    // the moment we get the list of keys and the moment we insert. So better not dawdle
    // between those.

    LDAPMod objectClassMod;
    objectClassMod.mod_op = LDAP_MOD_ADD;
    objectClassMod.mod_type = (char*)"objectClass";
    char* objectClassValues[] = { (char*)"top", (char*)"PdnsDomainKey", NULL };
    objectClassMod.mod_values = objectClassValues;

    LDAPMod keyidMod;
    keyidMod.mod_op = LDAP_MOD_ADD;
    keyidMod.mod_type = (char*)"PdnsKeyId";

    LDAPMod keyflagsMod;
    keyflagsMod.mod_op = LDAP_MOD_ADD;
    keyflagsMod.mod_type = (char*)"PdnsKeyFlags";
    std::string keyflagsStr = std::to_string( key.flags );
    char* keyflagsValues[] = { (char*)keyflagsStr.c_str(), NULL };
    keyflagsMod.mod_values = keyflagsValues;

    LDAPMod keycontentMod;
    keycontentMod.mod_op = LDAP_MOD_ADD;
    keycontentMod.mod_type = (char*)"PdnsKeyContent";
    std::string escaped_keycontent = d_pldap->escape( key.content );
    char* keycontentValues[] = { (char*)escaped_keycontent.c_str(), NULL };
    keycontentMod.mod_values = keycontentValues;

    LDAPMod keyactiveMod;
    keyactiveMod.mod_op = LDAP_MOD_ADD;
    keyactiveMod.mod_type = (char*)"PdnsKeyActive";
    char* keyactiveValues[] = { (char*)"1", NULL };
    keyactiveMod.mod_values = keyactiveValues;

    /*
       Search for all the keys
    */
    int64_t maxId = 0;
    PowerLDAP::sentry_t keysearch_result;
    const char* keysearch_attributes[] = { "PdnsKeyId", NULL };
    PowerLDAP::SearchResult::Ptr search = d_pldap->search( basedn, LDAP_SCOPE_SUBTREE, "objectClass=PdnsDomainKey", keysearch_attributes );
    while ( search->getNext( keysearch_result, false ) ) {
      int64_t currentId = std::stoll( keysearch_result["PdnsKeyId"][0] );
      if ( currentId >= maxId )
        maxId = currentId + 1;
    }

    std::string maxIdStr = std::to_string( maxId );
    char* keyidValues[] = { (char*)maxIdStr.c_str(), NULL };
    keyidMod.mod_values = keyidValues;

    LDAPMod *mods[6];
    mods[0] = &objectClassMod;
    mods[1] = &keyidMod;
    mods[2] = &keyflagsMod;
    mods[3] = &keycontentMod;
    if ( key.active )
      mods[4] = &keyactiveMod;
    else
      mods[4] = NULL;
    mods[5] = NULL;

    std::string dn = "PdnsKeyId=" + maxIdStr + "," + basedn;
    g_log<<Logger::Debug<< d_myname << " Will create entry for the key at " << dn << std::endl;
    d_pldap->add( dn, mods );
    id = maxId;

    return true;
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
      return this->addDomainKey( name, key, id );
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
    g_log << Logger::Error << d_myname << " Caught STL exception adding key for domain " << name << ": " << e.what() << endl;
    throw DBException( "STL exception" );
  }
}


bool LdapBackend::activateDomainKey( const DNSName& name, unsigned int id )
{
  if ( !d_dnssec )
    return false;

  std::string basedn = this->getDomainMetadataDN( name );
  if ( basedn.empty() )
    return false;

  g_log<<Logger::Debug<< d_myname << " Activating key " << id << " on domain " << name << std::endl;

  try {
    PowerLDAP::sentry_t result;
    std::string filter = "(&(objectClass=PdnsDomainKey)(PdnsKeyId=" + std::to_string( id ) + "))";
    const char* attributes[] = { "PdnsKeyActive", NULL };
    PowerLDAP::SearchResult::Ptr search = d_pldap->search( basedn, LDAP_SCOPE_SUBTREE, filter, attributes );

    if ( !search->getNext( result, true ) ) {
      g_log<<Logger::Warning<< d_myname << " No key with this ID found" << std::endl;
      return false;
    }

    std::string dn = result["dn"][0];

    if ( !result.count( "PdnsKeyActive" ) ) {
      LDAPMod mod;
      mod.mod_op = LDAP_MOD_ADD;
      mod.mod_type = (char*)"PdnsKeyActive";
      char* modValues[] = { (char*)"1", NULL };
      mod.mod_values = modValues;

      LDAPMod* mods[2];
      mods[0] = &mod;
      mods[1] = NULL;

      d_pldap->modify( dn, mods );
    }

    return true;
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
      return this->activateDomainKey( name, id );
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
    g_log << Logger::Error << d_myname << " Caught STL exception activating key for domain " << name << ": " << e.what() << endl;
    throw DBException( "STL exception" );
  }
}


bool LdapBackend::deactivateDomainKey( const DNSName& name, unsigned int id )
{
  if ( !d_dnssec )
    return false;

  std::string basedn = this->getDomainMetadataDN( name );
  if ( basedn.empty() )
    return false;

  g_log<<Logger::Debug<< d_myname << " Deactivating key " << id << " on domain " << name << std::endl;

  try {
    PowerLDAP::sentry_t result;
    std::string filter = "(&(objectClass=PdnsDomainKey)(PdnsKeyId=" + std::to_string( id ) + "))";
    const char* attributes[] = { "PdnsKeyActive", NULL };
    PowerLDAP::SearchResult::Ptr search = d_pldap->search( basedn, LDAP_SCOPE_SUBTREE, filter, attributes );

    if ( !search->getNext( result, true ) ) {
      g_log<<Logger::Warning<< d_myname << " No key with this ID found" << std::endl;
      return false;
    }

    std::string dn = result["dn"][0];

    if ( result.count( "PdnsKeyActive" ) ) {
      LDAPMod mod;
      mod.mod_op = LDAP_MOD_DELETE;
      mod.mod_type = (char*)"PdnsKeyActive";

      LDAPMod* mods[2];
      mods[0] = &mod;
      mods[1] = NULL;

      d_pldap->modify( dn, mods );
    }

    return true;
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
      return this->deactivateDomainKey( name, id );
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
    g_log << Logger::Error << d_myname << " Caught STL exception deactivating key for domain " << name << ": " << e.what() << endl;
    throw DBException( "STL exception" );
  }
}


bool LdapBackend::removeDomainKey( const DNSName& name, unsigned int id )
{
  if ( !d_dnssec )
    return false;

  std::string basedn = this->getDomainMetadataDN( name );
  if ( basedn.empty() )
    return false;

  g_log<<Logger::Debug<< d_myname << " Removing key " << id << " on domain " << name << std::endl;

  try {
    PowerLDAP::sentry_t result;
    std::string filter = "(&(objectClass=PdnsDomainKey)(PdnsKeyId=" + std::to_string( id ) + "))";
    const char* attributes[] = { "PdnsKeyActive", NULL };
    PowerLDAP::SearchResult::Ptr search = d_pldap->search( basedn, LDAP_SCOPE_SUBTREE, filter, attributes );

    if ( !search->getNext( result, true ) ) {
      g_log<<Logger::Warning<< d_myname << " No key with this ID found" << std::endl;
      return true; // Eh, it's already not there, so everybody's happy, right?
    }

    std::string dn = result["dn"][0];
    d_pldap->del( dn );
    return true;
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
      return this->removeDomainKey( name, id );
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
    g_log << Logger::Error << d_myname << " Caught STL exception removing key for domain " << name << ": " << e.what() << endl;
    throw DBException( "STL exception" );
  }
}
 
 
bool LdapBackend::getTSIGKey( const DNSName& name, DNSName* algorithm, string* content )
{
  try {
    std::string filter = "(&(objectClass=PdnsTSIGKey)(cn=" + d_pldap->escape( name.toString( "" ) ) + "))";
    const char* attributes[] = { (char*)"PdnsKeyAlgorithm", (char*)"PdnsKeyContent", NULL };
    PowerLDAP::sentry_t result;
    PowerLDAP::SearchResult::Ptr search = d_pldap->search( "ou=TSIGKeys," + getArg( "metadata-searchdn" ), LDAP_SCOPE_ONELEVEL, filter, attributes );

    if ( !search->getNext( result ) )
      return false;

    if ( algorithm->empty() || *algorithm == DNSName( result["PdnsKeyAlgorithm"][0] ) ) {
      *algorithm = DNSName( result["PdnsKeyAlgorithm"][0] );
      *content = result["PdnsKeyContent"][0];
    }

    return !content->empty();
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
      return this->getTSIGKey( name, algorithm, content );
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
    g_log << Logger::Error << d_myname << " Caught STL exception retrieving TSIG key '" << name << "': " << e.what() << endl;
    throw DBException( "STL exception" );
  }
}


bool LdapBackend::setTSIGKey( const DNSName& name, const DNSName& algorithm, const string& content )
{
  try {
    DNSName existingAlgo;
    std::string existingContent;
    if ( this->getTSIGKey( name, &existingAlgo, &existingContent ) ) {
      LDAPMod algoMod;
      algoMod.mod_op = LDAP_MOD_REPLACE;
      algoMod.mod_type = (char*)"PdnsKeyAlgorithm";
      std::string algoStr = algorithm.toString( "" );
      char* algoValues[] = { (char*)(algoStr.c_str()), NULL };
      algoMod.mod_values = algoValues;

      LDAPMod contentMod;
      contentMod.mod_op = LDAP_MOD_REPLACE;
      contentMod.mod_type = (char*)"PdnsKeyContent";
      char* contentValues[] = { (char*)(content.c_str()), NULL };
      contentMod.mod_values = contentValues;

      std::string filter = "(&(objectClass=PdnsTSIGKey)(cn=" + d_pldap->escape( name.toString( "" ) ) + "))";
      const char* attributes[] = { (char*)"objectClass", NULL };
      PowerLDAP::sentry_t result;
      PowerLDAP::SearchResult::Ptr search = d_pldap->search( "ou=TSIGKeys," + getArg( "metadata-searchdn" ), LDAP_SCOPE_ONELEVEL, filter, attributes );

      LDAPMod* mods[3];
      mods[0] = &algoMod;
      mods[1] = &contentMod;
      mods[2] = NULL;

      if ( !search->getNext( result, true ) ) // Whaaaa?
        return false;

      d_pldap->modify( result["dn"][0], mods );
    }
    else {
      LDAPMod objectClassMod;
      objectClassMod.mod_op = LDAP_MOD_ADD;
      objectClassMod.mod_type = (char*)"objectClass";
      char* objectClassValues[] = { (char*)"top", (char*)"PdnsTSIGKey", NULL };
      objectClassMod.mod_values = objectClassValues;

      LDAPMod cnMod;
      cnMod.mod_op = LDAP_MOD_ADD;
      cnMod.mod_type = (char*)"cn";
      std::string cnStr = name.toString( "" );
      char* cnValues[] = { (char*)(cnStr.c_str()), NULL };
      cnMod.mod_values = cnValues;

      LDAPMod algoMod;
      algoMod.mod_op = LDAP_MOD_ADD;
      algoMod.mod_type = (char*)"PdnsKeyAlgorithm";
      std::string algoStr = algorithm.toString( "" );
      char* algoValues[] = { (char*)(algoStr.c_str()), NULL };
      algoMod.mod_values = algoValues;

      LDAPMod contentMod;
      contentMod.mod_op = LDAP_MOD_ADD;
      contentMod.mod_type = (char*)"PdnsKeyContent";
      char* contentValues[] = { (char*)(content.c_str()), NULL };
      contentMod.mod_values = contentValues;

      LDAPMod* mods[5];
      mods[0] = &objectClassMod;
      mods[1] = &cnMod;
      mods[2] = &algoMod;
      mods[3] = &contentMod;
      mods[4] = NULL;

      std::string dn = "cn=" + cnStr + ",ou=TSIGKeys," + getArg( "metadata-searchdn" );
      g_log<<Logger::Debug<< d_myname << " Adding a TSIG key named '" << cnStr << "' at '" << dn << "'" << std::endl;
      d_pldap->add( dn, mods );
    }

    return true;
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
      return this->setTSIGKey( name, algorithm, content );
    else
      throw PDNSException( "Failed to reconnect to LDAP server" );
  }
  catch( LDAPException &le )
  {
    g_log << Logger::Error << d_myname << " Unable to set TSIG key in LDAP: " << le.what() << endl;
    throw PDNSException( "LDAP server unreachable" );   // try to reconnect to another server
  }
  catch( std::exception &e )
  {
    g_log << Logger::Error << d_myname << " Caught STL exception adding TSIG key '" << name << "': " << e.what() << endl;
    throw DBException( "STL exception" );
  }
}


bool LdapBackend::deleteTSIGKey( const DNSName& name )
{
  try {
    std::string filter = "(&(objectClass=PdnsTSIGKey)(cn=" + d_pldap->escape( name.toString( "" ) ) + "))";
    const char* attributes[] = { (char*)"objectClass", NULL };
    PowerLDAP::sentry_t result;
    PowerLDAP::SearchResult::Ptr search = d_pldap->search( "ou=TSIGKeys," + getArg( "metadata-searchdn" ), LDAP_SCOPE_ONELEVEL, filter, attributes );

    if ( !search->getNext( result, true ) )
      return false;

    d_pldap->del( result["dn"][0] );

    return true;
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
      return this->deleteTSIGKey( name );
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
    g_log << Logger::Error << d_myname << " Caught STL exception deleting TSIG key '" << name << "': " << e.what() << endl;
    throw DBException( "STL exception" );
  }
}


bool LdapBackend::getTSIGKeys( std::vector<struct TSIGKey>& keys )
{
  try {
    std::string filter = "objectClass=PdnsTSIGKey";
    const char* attributes[] = { (char*)"cn", (char*)"PdnsKeyAlgorithm", (char*)"PdnsKeyContent", NULL };
    PowerLDAP::sentry_t result;
    PowerLDAP::SearchResult::Ptr search = d_pldap->search( "ou=TSIGKeys," + getArg( "metadata-searchdn" ), LDAP_SCOPE_ONELEVEL, filter, attributes );

    while ( search->getNext( result, false ) ) {
      TSIGKey key;
      key.name = DNSName( result["cn"][0] );
      key.algorithm = DNSName( result["PdnsKeyAlgorithm"][0] );
      key.key = result["PdnsKeyContent"][0];
      keys.push_back( key );
    }

    return true;
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
      return this->getTSIGKeys( keys );
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
    g_log << Logger::Error << d_myname << " Caught STL exception retrieving all TSIG keys: " << e.what() << endl;
    throw DBException( "STL exception" );
  }
}
 
 
bool LdapBackend::getBeforeAndAfterNamesAbsolute( uint32_t domain_id, const DNSName& qname, DNSName& unhashed, DNSName& before, DNSName& after )
{
  if ( !d_dnssec )
    return false;

  g_log<<Logger::Debug<< d_myname << " Searching for names before and after " << unhashed << ", qname: " << qname << ", domain_id: " << domain_id << std::endl;

  try {
    // Get the zone first
    std::string filter = "PdnsDomainId=" + std::to_string( domain_id );
    const char* zoneAttributes[] = { "associatedDomain", NULL };
    PowerLDAP::sentry_t result;

    PowerLDAP::SearchResult::Ptr search = d_pldap->search( getArg( "basedn" ), LDAP_SCOPE_SUBTREE, filter, zoneAttributes );
    if ( !search->getNext( result, true ) ) {
      g_log<<Logger::Debug<< d_myname << " Can't find the zone for domain ID " << domain_id << std::endl;
      return false;
    }

    std::string basedn = getArg( "basedn" );
    if ( mustDo( "lookup-zone-rebase" ) )
      basedn = result["dn"][0];

    std::string qnameMatch = ( qname.empty() || qname.isRoot() ) ? " " : qname.labelReverse().toString( " ", false );
    std::string foundBeforeOrdername, foundBeforeDomain, foundAfter;
    std::string domainBase = result["associatedDomain"][0];
    const char* orderAttributes[] = { "associatedDomain", "PdnsRecordOrdername", NULL };
    filter = "(&(|(associatedDomain="+domainBase+")(associatedDomain=*."+domainBase+"))(PdnsRecordOrdername>="+d_pldap->escape(qnameMatch)+"))";

    search = d_pldap->sorted_search( basedn, LDAP_SCOPE_SUBTREE, filter, std::string( "PdnsRecordOrdername" ), orderAttributes, 2 );
    if ( search ) {
      g_log<<Logger::Debug<< d_myname << " Sorting is available on this server" << std::endl;

      // Sorting sometimes fail because the LDAP server cannot honor it.
      // Retry the search for at most 3 times, and if it works, yay!
      int retryAttempts = 3;
      while ( retryAttempts > 0 ) {
        while ( search->getNext( result, false ) ) {
          foundAfter = result["PdnsRecordOrdername"][0];
          if ( foundAfter > qnameMatch )
            break;
        }

        search->consumeAll();
        if ( search->successful() )
          break;

        g_log<<Logger::Error<< d_myname << " Name after search failed (code '" << search->status() << "'): " << search->error() << std::endl;
        search = d_pldap->sorted_search( basedn, LDAP_SCOPE_SUBTREE, filter, std::string( "PdnsRecordOrdername" ), orderAttributes, 2 );
        --retryAttempts;
      }
      if ( retryAttempts == 0 && !search->successful() ) {
        throw PDNSException( "Name after search failed: " + search->error() );
      }

      if ( foundAfter.empty() ) {
        // This was the last entry in the zone, get the first
        filter = "(&(|(associatedDomain="+domainBase+")(associatedDomain=*."+domainBase+"))(PdnsRecordOrdername=*))";
        search = d_pldap->sorted_search( basedn, LDAP_SCOPE_SUBTREE, filter, std::string( "PdnsRecordOrdername" ), orderAttributes, 1 );

        // Same as above, retry at most 3 times
        retryAttempts = 3;
        while ( retryAttempts > 0 ) {
          if ( search->getNext( result, false ) )
            foundAfter = result["PdnsRecordOrdername"][0];

          search->consumeAll();
          if ( search->successful() )
            break;

          g_log<<Logger::Error<< d_myname << " Name after search failed (zone start): " << search->error() << std::endl;
          search = d_pldap->sorted_search( basedn, LDAP_SCOPE_SUBTREE, filter, std::string( "PdnsRecordOrdername" ), orderAttributes, 1 );
          --retryAttempts;
        }
        if ( retryAttempts == 0 && !search->successful() ) {
          throw PDNSException( "Name after search failed (zone start): " + search->error() );
        }
      }

      g_log<<Logger::Debug<< d_myname << "     Found after: " << foundAfter << std::endl;

      filter = "(&(|(associatedDomain="+domainBase+")(associatedDomain=*."+domainBase+"))(PdnsRecordOrdername<="+d_pldap->escape(qnameMatch)+"))";
      search = d_pldap->sorted_search( basedn, LDAP_SCOPE_SUBTREE, filter, std::string( "-PdnsRecordOrdername" ), orderAttributes, 1 );
      // Same as above, retry at most 3 times
      retryAttempts = 3;
      while ( retryAttempts > 0 ) {
        if ( search->getNext( result, false ) ) {
          foundBeforeOrdername = result["PdnsRecordOrdername"][0];
          foundBeforeDomain = result["associatedDomain"][0];
        }

        search->consumeAll();
        if ( search->successful() )
          break;

        g_log<<Logger::Error<< d_myname << " Name before search failed: " << search->error() << std::endl;
        search = d_pldap->sorted_search( basedn, LDAP_SCOPE_SUBTREE, filter, std::string( "-PdnsRecordOrdername" ), orderAttributes, 1 );
        --retryAttempts;
      }
      if ( retryAttempts == 0 && !search->successful() ) {
        throw PDNSException( "Name before search failed: " + search->error() );
      }

      if ( foundBeforeOrdername.empty() ) {
        // This was the first entry in the zone, get the last
        filter = "(&(|(associatedDomain="+domainBase+")(associatedDomain=*."+domainBase+"))(PdnsRecordOrdername=*))";
        search = d_pldap->sorted_search( basedn, LDAP_SCOPE_SUBTREE, filter, std::string( "-PdnsRecordOrdername" ), orderAttributes, 1 );

        // Same old, 3 times
        retryAttempts = 3;
        while ( retryAttempts > 0 ) {
          if ( search->getNext( result, false ) ) {
            foundBeforeOrdername = result["PdnsRecordOrdername"][0];
            foundBeforeDomain = result["associatedDomain"][0];
          }

          search->consumeAll();
          if ( search->successful() )
            break;

          g_log<<Logger::Error<< d_myname << " Name before search failed (zone end): " << search->error() << std::endl;
          search = d_pldap->sorted_search( basedn, LDAP_SCOPE_SUBTREE, filter, std::string( "-PdnsRecordOrdername" ), orderAttributes, 1 );
          --retryAttempts;
        }
        if ( retryAttempts == 0 && !search->successful() ) {
          throw PDNSException( "Name before search failed: " + search->error() );
        }
      }

      g_log<<Logger::Debug<< d_myname << "     Found before: " << foundBeforeOrdername << " (" << foundBeforeDomain << ")" << std::endl;
    }
    else {
      // No sorting available on this server, do it manually
      std::map<std::string, std::string> ordernames;
      filter = "(&(|(associatedDomain="+domainBase+")(associatedDomain=*."+domainBase+"))(PdnsRecordOrdername=*))";
      search = d_pldap->search( basedn, LDAP_SCOPE_SUBTREE, filter, orderAttributes );
      g_log<<Logger::Debug<< d_myname << " Subdomains search done" << std::endl;

      while ( search->getNext( result, false ) ) {
        // No need to iterate over associatedDomain as for DNSSEC I doubt that having more
        // than one value for this attribute is going to work.
        ordernames[result["PdnsRecordOrdername"][0]] = result["associatedDomain"][0];
      }
      g_log<<Logger::Debug<< d_myname << " Subdomains ordernames retrieved" << std::endl;

      for ( const auto& ordername : ordernames ) {
        if ( ordername.first <= qnameMatch ) {
          foundBeforeOrdername = ordername.first;
          foundBeforeDomain = ordername.second;
        }
        else if ( foundAfter.empty() && ordername.first > qnameMatch ) {
          foundAfter = ordername.first;
        }
      }
      g_log<<Logger::Debug<< d_myname << " before / after search done" << std::endl;

      if ( foundAfter.empty() )
        foundAfter = ordernames.begin()->first;

      if ( foundBeforeDomain.empty() ) {
        foundBeforeOrdername = ordernames.rbegin()->first;
        foundBeforeDomain = ordernames.rbegin()->second;
      }
    }
 
    if ( foundAfter.empty() )
      throw PDNSException( "Failed to find the name after '" + qname.toString() + "'" );

    if ( foundBeforeOrdername.empty() )
      throw PDNSException( "Failed to find the name before '" + qname.toString() + "'" );

    after = DNSName( boost::replace_all_copy( foundAfter, " ", "." ) ).labelReverse();

    // What follows is how the GSQL backend works. I just took the algorithm as-is, but no comments exist,
    // so I have no idea what I'm doing exactly right now.
    if ( before.empty() ) {
      before = DNSName( boost::replace_all_copy( foundBeforeOrdername, " ", "." ) ).labelReverse();
      unhashed = DNSName( foundBeforeDomain );
    }
    else {
      before = qname;
    }

    g_log<<Logger::Debug<< d_myname << "     Found before=" << before << ", after=" << after << ", unhashed=" << unhashed << std::endl;

    return true;
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
      return this->getBeforeAndAfterNamesAbsolute( domain_id, qname, unhashed, before, after );
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
    g_log << Logger::Error << d_myname << " Caught STL exception getting before and after names for " << qname << ": " << e.what() << endl;
    throw DBException( "STL exception" );
  }
}


bool LdapBackend::updateDNSSECOrderNameAndAuth( uint32_t domain_id, const DNSName& qname, const DNSName& ordername, bool auth, const uint16_t qtype )
{
  if ( !d_dnssec )
    return false;

  g_log<<Logger::Debug<< d_myname << " Updating ordername and auth for " << qname << ", ordername=" << ordername << ", auth=" << auth << ", qtype=" << QType( qtype ).getName() << std::endl;

  try {
    // Get the zone first
    std::string filter = "PdnsDomainId=" + std::to_string( domain_id );
    const char* zoneAttributes[] = { "associatedDomain", NULL };
    PowerLDAP::sentry_t result;

    PowerLDAP::SearchResult::Ptr search = d_pldap->search( getArg( "basedn" ), LDAP_SCOPE_SUBTREE, filter, zoneAttributes );
    if ( !search->getNext( result, true ) ) {
      g_log<<Logger::Debug<< d_myname << " Can't find the zone for domain ID " << domain_id << std::endl;
      return false;
    }

    std::string basedn = getArg( "basedn" );
    if ( mustDo( "lookup-zone-rebase" ) )
      basedn = result["dn"][0];

    // Get the record to assess the changes to perform
    filter = "associatedDomain=" + d_pldap->escape( qname.toStringRootDot() );
    filter = strbind( ":target:", filter, getArg( "filter-lookup" ) );

    search = d_pldap->search( basedn, LDAP_SCOPE_SUBTREE, filter, (const char**)ldap_attrany );
    if ( !search->getNext( result, true ) )
      return false;


    // We have first to make sure that the entry has the correct object class
    bool addObjectClass = true;
    for ( const auto& oc : result["objectClass"] )
      if ( oc == "PdnsRecordData" )
        addObjectClass = false;

    if ( addObjectClass ) {
      g_log<<Logger::Debug<< d_myname << " Adding PdnsRecordData object class on " << result["dn"][0] << std::endl;
      LDAPMod mod;
      mod.mod_op = LDAP_MOD_ADD;
      mod.mod_type = (char*)"objectClass";
      char* ocValues[] = { (char*)"PdnsRecordData", NULL };
      mod.mod_values = ocValues;

      LDAPMod* mods[2];
      mods[0] = &mod;
      mods[1] = NULL;

      d_pldap->modify( result["dn"][0], mods );
    }

    // Now let's extract the relevant information from the entry
    std::set<std::string>              entryRRs,       // The RRs in it
                                       entryNoAuthRRs, // The RRs on which this entry is not authoritative
                                       entryNoONRRs;   // The RRs for which this entry has no ordername
    std::string entryOrdername;
    std::string convertedOrdername;
    if ( !ordername.empty() )
      convertedOrdername = ordername.labelReverse().toString( " ", false );
    if ( convertedOrdername.empty() )
      convertedOrdername = " ";
    std::string qtypeName = QType( qtype ).getName();

    for ( const auto& attribute : result ) {
      if ( attribute.first.length() > 6 && attribute.first.substr( attribute.first.length() - 6 ) == "Record" ) {
        entryRRs.insert( toUpper( attribute.first.substr( 0, attribute.first.length() - 6 ) ) );
      }
      else if ( attribute.first == "PdnsRecordNoAuth" ) {
        for ( const auto& noauth : attribute.second )
          entryNoAuthRRs.insert( noauth );
      }
      else if ( attribute.first == "PdnsRecordOrdername" ) {
        entryOrdername = attribute.second[0];
      }
      else if ( attribute.first == "PdnsRecordNoOrdername" ) {
        for ( const auto& noON : attribute.second ) {
          entryNoONRRs.insert( noON );
        }
      }
    }

    if ( qtype == QType::ANY ) {
      if ( auth && entryNoAuthRRs.size() ) {
        g_log<<Logger::Debug<< d_myname << " Removing all PdnsRecordNoAuth attributes from " << result["dn"][0] << std::endl;
        LDAPMod mod;
        mod.mod_op = LDAP_MOD_DELETE;
        mod.mod_type = (char*)"PdnsRecordNoAuth";
        mod.mod_values = { NULL };

        LDAPMod* mods[2];
        mods[0] = &mod;
        mods[1] = NULL;

        d_pldap->modify( result["dn"][0], mods );
      }
      else if ( !auth ) {
        // We have to look at the attributes present in the entry and add a PdnsRecordNoAuth
        // for all RRs that don't have one.
        std::set<std::string> missingNoAuth;
        std::set_difference( entryRRs.begin(), entryRRs.end(),
                             entryNoAuthRRs.begin(), entryNoAuthRRs.end(),
                             std::inserter( missingNoAuth, missingNoAuth.end() ) );
        for ( const auto& rrtype : missingNoAuth ) {
          g_log<<Logger::Debug<< d_myname << " Add PdnsRecordNoAuth for RR " << rrtype << " on " << result["dn"][0] << std::endl;
          LDAPMod mod;
          mod.mod_op = LDAP_MOD_ADD;
          mod.mod_type = (char*)"PdnsRecordNoAuth";
          char* recordValues[] = { (char*)rrtype.c_str(), NULL };
          mod.mod_values = recordValues;

          LDAPMod* mods[2];
          mods[0] = &mod;
          mods[1] = NULL;

          d_pldap->modify( result["dn"][0], mods );
        }
      }

      if ( ordername.empty() && result.count( "PdnsRecordOrdername" ) ) {
        // Easy as pie, just remove all the ordername attributes
        g_log<<Logger::Debug<< d_myname << " Deleting all ordernames" << std::endl;

        LDAPMod mod;
        mod.mod_op = LDAP_MOD_DELETE;
        mod.mod_type = (char*)"PdnsRecordOrdername";
        mod.mod_values = { NULL };

        LDAPMod* mods[2];
        mods[0] = &mod;
        mods[1] = NULL;
        d_pldap->modify( result["dn"][0], mods );
      }
      else if ( !ordername.empty() && entryOrdername != convertedOrdername ) {
        // This sets the entry default ordername, meaning that all RR-specific ordernames
        // are to be deleted. So long _o/
        // Take the easy way: delete all and recreate the default one.
        g_log<<Logger::Debug<< d_myname << " Setting default entry ordername, deleting others" << std::endl;

        LDAPMod* mods[4];

        LDAPMod delMod;
        delMod.mod_op = LDAP_MOD_DELETE;
        delMod.mod_type = (char*)"PdnsRecordOrdername";
        delMod.mod_values = { NULL };

        LDAPMod addMod;
        addMod.mod_op = LDAP_MOD_ADD;
        addMod.mod_type = (char*)"PdnsRecordOrdername";
        std::string addStr = convertedOrdername;
        char* addValues[] = { (char*)addStr.c_str(), NULL };
        addMod.mod_values = addValues;
 
        LDAPMod delNoONMod;
        delNoONMod.mod_op = LDAP_MOD_DELETE;
        delNoONMod.mod_type = (char*)"PdnsRecordNoOrdername";
        delNoONMod.mod_values = { NULL };

        if ( result.count( "PdnsRecordOrdername" ) ) {
          mods[0] = &delMod;
          mods[1] = &addMod;
          if ( !entryNoONRRs.empty() )
            mods[2] = &delNoONMod;
          else
            mods[2] = NULL;
        }
        else {
          mods[0] = &addMod;
          if ( !entryNoONRRs.empty() )
            mods[1] = &delNoONMod;
          else
            mods[1] = NULL;
          mods[2] = NULL;
        }

        mods[3] = NULL;

        d_pldap->modify( result["dn"][0], mods );
      }
    }
    else {
      if ( auth && entryNoAuthRRs.count( qtypeName ) ) {
        g_log<<Logger::Debug<< d_myname << " Deleting PdnsRecordNoAuth=" << qtypeName << std::endl;

        LDAPMod mod;
        mod.mod_op = LDAP_MOD_DELETE;
        mod.mod_type = (char*)"PdnsRecordNoAuth";
        char* deleteValues[] = { (char*)( qtypeName.c_str() ), NULL };
        mod.mod_values = deleteValues;

        LDAPMod* mods[2];
        mods[0] = &mod;
        mods[1] = NULL;

        d_pldap->modify( result["dn"][0], mods );
      }
      else if ( !auth && !entryNoAuthRRs.count( qtypeName ) ) {
        g_log<<Logger::Debug<< d_myname << " Adding PdnsRecordNoAuth=" << qtypeName << std::endl;

        LDAPMod mod;
        mod.mod_op = LDAP_MOD_ADD;
        mod.mod_type = (char*)"PdnsRecordNoAuth";
        char* addValues[] = { (char*)( qtypeName.c_str() ), NULL };
        mod.mod_values = addValues;

        LDAPMod* mods[2];
        mods[0] = &mod;
        mods[1] = NULL;

        d_pldap->modify( result["dn"][0], mods );
      }

      // Setting a RR-specific non-empty ordername is not supported by this backend
      if ( !ordername.empty() ) {
        if ( convertedOrdername != entryOrdername )
          throw PDNSException( "Unsupported operation: adding a different, non-empty ordername for a RR" );
      }
      else {
        std::set<std::string> remainingONs = entryRRs;
        if ( remainingONs.count( qtypeName ) )
          remainingONs.erase( qtypeName );
        for ( const auto& rr : entryNoONRRs )
          remainingONs.erase( rr );

        if ( result.count( "PdnsRecordOrdername" ) ) {
          if ( !remainingONs.size() ) {
            g_log<<Logger::Debug<< d_myname << " Removing PdnsRecordOrdername as the last RR will be deleted" << std::endl;

            LDAPMod mod;
            mod.mod_op = LDAP_MOD_DELETE;
            mod.mod_type = (char*)"PdnsRecordOrdername";
            mod.mod_values = { NULL };

            LDAPMod delNoONMod;
            delNoONMod.mod_op = LDAP_MOD_DELETE;
            delNoONMod.mod_type = (char*)"PdnsRecordNoOrdername";
            delNoONMod.mod_values = { NULL };

            LDAPMod* mods[3];
            mods[0] = &mod;
            if ( !entryNoONRRs.empty() )
              mods[1] = &delNoONMod;
            else
              mods[1] = NULL;
            mods[2] = NULL;

            d_pldap->modify( result["dn"][0], mods );
          }
          else if ( !entryNoONRRs.count( qtypeName ) ) {
            g_log<<Logger::Debug<< d_myname << " Setting PdnsRecordNoOrdername for qtype " << qtypeName << std::endl;

            LDAPMod addMod;
            addMod.mod_op = LDAP_MOD_ADD;
            addMod.mod_type = (char*)"PdnsRecordNoOrdername";
            char* addValues[] = { (char*)qtypeName.c_str(), NULL };
            addMod.mod_values = addValues;

            LDAPMod* mods[2];
            mods[0] = &addMod;
            mods[1] = NULL;

            d_pldap->modify( result["dn"][0], mods );
          }
        }
      }
    }

    return true;
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
      return this->updateDNSSECOrderNameAndAuth( domain_id, qname, ordername, auth, qtype );
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
    g_log << Logger::Error << d_myname << " Caught STL exception updating DNSSEC ordername and auth for " << qname << ": " << e.what() << endl;
    throw DBException( "STL exception" );
  }
}
