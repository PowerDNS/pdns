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
 

bool LdapBackend::updateDNSSECOrderNameAndAuth( uint32_t domain_id, const DNSName& qname, const DNSName& ordername, bool auth, const uint16_t qtype )
{
  if ( !d_dnssec )
    return false;

  g_log<<Logger::Debug<< d_myname << " Updating ordername and auth for " << qname << ", ordername=" << ordername << ", auth=" << auth << ", qtype=" << QType( qtype ).getName() << std::endl;

  try {
    // Get the zone first
    DNSName zonename;
    std::string filter = "PdnsDomainId=" + std::to_string( domain_id );
    const char* zoneAttributes[] = { "associatedDomain", NULL };
    PowerLDAP::sentry_t result;

    PowerLDAP::SearchResult::Ptr search = d_pldap->search( getArg( "basedn" ), LDAP_SCOPE_SUBTREE, filter, zoneAttributes );
    if ( !search->getNext( result, true ) ) {
      g_log<<Logger::Debug<< d_myname << " Can't find the zone for domain ID " << domain_id << std::endl;
      return false;
    }
    zonename = DNSName( result["associatedDomain"][0] );

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
                                       entryNoAuthRRs; // The RRs on which this entry is not authoritative
    std::map<std::string, std::string> entryONRRs;     // And the ones with a specific ordername
    std::string entryOrdername;
    std::string convertedOrdername;
    if ( !ordername.empty() )
      convertedOrdername = ordername.makeRelative( zonename ).labelReverse().toString( " ", false );
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
        for ( const auto& rrOrdername : attribute.second ) {
          std::size_t pos = rrOrdername.find_first_of( '|', 0 );
          if ( pos == std::string::npos ) {
            entryOrdername = rrOrdername;
          }
          else {
            entryONRRs.insert(
                std::make_pair(
                  rrOrdername.substr( 0, pos ),
                  rrOrdername.substr( pos + 1 )
                )
              );
          }
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

        LDAPMod* mods[3];

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

        if ( result.count( "PdnsOrdername" ) ) {
          mods[0] = &delMod;
          mods[1] = &addMod;
        }
        else {
          mods[0] = &addMod;
          mods[1] = NULL;
        }

        mods[2] = NULL;

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

      // For the ordername, whatever its value, this will override the default entry ordername.
      // However, setting an empty ordername on all attribute types held by this entry means
      // that we have to delete all ordernames.
      std::set<std::string> remainingONs = entryRRs;
      if ( remainingONs.count( qtypeName ) )
        remainingONs.erase( qtypeName );
      for ( const auto& rr : entryONRRs )
        if ( remainingONs.count( rr.first ) && rr.second.empty() )
          remainingONs.erase( rr.first );

      if ( ordername.empty() && result.count( "PdnsRecordOrdername" ) && !remainingONs.size() ) {
          g_log<<Logger::Debug<< d_myname << " Removing PdnsRecordOrdername as the last RR will be deleted" << std::endl;

          LDAPMod mod;
          mod.mod_op = LDAP_MOD_DELETE;
          mod.mod_type = (char*)"PdnsRecordOrdername";
          mod.mod_values = { NULL };

          LDAPMod* mods[2];
          mods[0] = &mod;
          mods[1] = NULL;

          d_pldap->modify( result["dn"][0], mods );
      }
      else if ( entryOrdername != convertedOrdername && ( !entryONRRs.count( qtypeName ) || entryONRRs[qtypeName] != convertedOrdername ) && ( entryRRs.count( qtypeName ) ) ) {
        g_log<<Logger::Debug<< d_myname << " Setting ordername to " << convertedOrdername << " for RR " << qtypeName << std::endl;
        LDAPMod* mods[3];

        LDAPMod delMod;
        delMod.mod_op = LDAP_MOD_DELETE;
        delMod.mod_type = (char*)"PdnsRecordOrdername";
        std::string delStr;
        char* delValues[] = { NULL, NULL };
        delMod.mod_values = delValues;

        LDAPMod addMod;
        addMod.mod_op = LDAP_MOD_ADD;
        addMod.mod_type = (char*)"PdnsRecordOrdername";
        std::string rrOrdername = ordername.empty() ? "" : convertedOrdername;
        std::string addStr = qtypeName + "|" + rrOrdername;
        char* addValues[] = { (char*)addStr.c_str(), NULL };
        addMod.mod_values = addValues;

        if ( entryONRRs.count( qtypeName ) && entryONRRs[qtypeName] != rrOrdername ) {
          delStr = qtypeName + "|" + entryONRRs[qtypeName];
          delValues[0] = (char*)delStr.c_str();
          mods[0] = &delMod;
          mods[1] = &addMod;
        }
        else {
          mods[0] = &addMod;
          mods[1] = NULL;
        }

        mods[2] = NULL;

        d_pldap->modify( result["dn"][0], mods );
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
