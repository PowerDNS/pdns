/*
 *  PowerDNS LDAP Backend
 *  Copyright (C) 2003 Norbert Sendetzky <norbert@linuxnetworks.de>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */



#include "ldapbackend.hh"



LdapBackend::LdapBackend( const string &suffix )
{
	unsigned int i;
	setArgPrefix( "ldap" + suffix );
	string hosts = getArg( "host" );

	m_msgid = 0;
	m_qname = "";
	m_default_ttl = arg().asNum( "default-ttl" );
	m_pldap = NULL;

	for( i = 0; i < hosts.length(); i++ )
	{
		if( hosts[i] == ',' ) { hosts[i] = ' '; }
	}

	L << Logger::Info << backendname << " LDAP servers = " << hosts << endl;

	try
	{
		m_pldap = new PowerLDAP( hosts.c_str(), atoi( getArg( "port" ).c_str() ), mustDo( "starttls" ) );
		m_pldap->setOption( LDAP_OPT_DEREF, LDAP_DEREF_ALWAYS );
		m_pldap->simpleBind( getArg( "binddn" ), getArg( "secret" ) );
	}
	catch( LDAPException &e )
	{
		L << Logger::Error << backendname << " Initialization failed: " << e.what() << endl;
		if( m_pldap != NULL ) { delete( m_pldap ); }
		throw( AhuException( "Unable to connect to ldap server" ) );
	}

	L << Logger::Notice << backendname << " Ldap connection succeeded" << endl;
}


LdapBackend::~LdapBackend()
{
	delete( m_pldap );
	L << Logger::Notice << backendname << " Ldap connection closed" << endl;
}


bool LdapBackend::list( const string &target, int domain_id )
{
	string filter;


	try
	{
		m_qname = target;
		m_axfrqlen = target.length();
		m_adomain = m_adomains.end();   // skip loops in get() first time

		filter = "(|(associatedDomain=" + target + ")(associatedDomain=*." + target + "))";
		m_msgid = m_pldap->search( getArg("basedn"), LDAP_SCOPE_SUBTREE, filter, (const char**) attrany );
	}
	catch( LDAPTimeout &lt )
	{
		L << Logger::Warning << backendname << " Unable to get zone " + target + " from LDAP directory: " << lt.what() << endl;
		return false;
	}
	catch( LDAPException &le )
	{
		L << Logger::Error << backendname << " Unable to get zone " + target + " from LDAP directory: " << le.what() << endl;
		throw( AhuException( "LDAP server unreachable" ) );   // try to reconnect to another server
	}
	catch( exception &e )
	{
		L << Logger::Error << backendname << " Caught STL exception for target " << target << ": " << e.what() << endl;
		return false;
	}
	catch( ... )
	{
		L << Logger::Critical << backendname << " Caught unknown exception for target " << target << endl;
		return false;
	}

	return true;
}


void LdapBackend::lookup( const QType &qtype, const string &qname, DNSPacket *dnspkt, int zoneid )
{
	int len;
	vector<string> parts;
	string filter, attr, qesc;
	char** attributes = attrany + 1;   // skip associatedDomain
	char* attronly[] = { NULL, "dNSTTL", NULL };


	try
	{
		m_axfrqlen = 0;
		m_qtype = qtype;
		m_qname = qname;
		qesc = toLower( m_pldap->escape( qname ) );

		if( mustDo( "disable-ptrrecord" ) )  // PTRRecords will be derived from aRecords or aAAARecords
		{
			stringtok( parts, qesc, "." );
			len = qesc.length();

			 if( parts.size() == 6 && len > 13 && qesc.substr( len - 13, 13 ) == ".in-addr.arpa" )   // IPv4 reverse lookups
			{
				filter = "(aRecord=" + ptr2ip4( parts ) + ")";
				attronly[0] = "associatedDomain";
				attributes = attronly;
			}
			else if( parts.size() == 34 && len > 9 && ( qesc.substr( len - 9, 9 ) == ".ip6.arpa" ) )   // IPv6 reverse lookups
			{
				filter = "(aAAARecord=" + ptr2ip6( parts ) + ")";
				attronly[0] = "associatedDomain";
				attributes = attronly;
			}
			else   // IPv4 and IPv6 lookups
			{
				filter = "(associatedDomain=" + qesc + ")";
				if( qtype.getCode() != QType::ANY )
				{
					attr = qtype.getName() + "Record";
					filter = "(&" + filter + "(" + attr + "=*))";
					attronly[0] = (char*) attr.c_str();
					attributes = attronly;
				}
			}
		}
		else   // requires additional ldap objects for reverse lookups
		{
			filter = "(associatedDomain=" + qesc + ")";
			if( qtype.getCode() != QType::ANY )
			{
				attr = qtype.getName() + "Record";
				filter = "(&" + filter + "(" + attr + "=*))";
				attronly[0] = (char*) attr.c_str();
				attributes = attronly;
			}
		}

		DLOG( L << Logger::Debug << backendname << " Search = basedn: " << getArg( "basedn" ) << ", filter: " << filter << ", qtype: " << qtype.getName() << endl );

		m_adomain = m_adomains.end();   // skip loops in get() first time
		m_msgid = m_pldap->search( getArg("basedn"), LDAP_SCOPE_SUBTREE, filter, (const char**) attributes );
	}
	catch( LDAPTimeout &lt )
	{
		L << Logger::Warning << backendname << " Unable to search LDAP directory: " << lt.what() << endl;
		return;
	}
	catch( LDAPException &le )
	{
		L << Logger::Error << backendname << " Unable to search LDAP directory: " << le.what() << endl;
		throw( AhuException( "LDAP server unreachable" ) );   // try to reconnect to another server
	}
	catch( exception &e )
	{
		L << Logger::Error << backendname << " Caught STL exception for qname " << qname << ": " << e.what() << endl;
		return;
	}
	catch( ... )
	{
		L << Logger::Critical << backendname << " Caught unknown exception for qname " << qname << endl;
		return;
	}
}


bool LdapBackend::get( DNSResourceRecord &rr )
{
	QType qt;
	vector<string> parts;
	string attrname, content, qstr;


	try
	{
		do
		{
			while( m_adomain != m_adomains.end() )
			{
				while( m_attribute != m_result.end() )
				{
					attrname = m_attribute->first;
					qstr = attrname.substr( 0, attrname.length() - 6 );   // extract qtype string from ldap attribute name
					qt = QType( const_cast<char*>(toUpper( qstr ).c_str()) );

					while( m_value != m_attribute->second.end() )
					{
						content = *m_value;

						rr.qtype = qt;
						rr.qname = *m_adomain;
						rr.priority = 0;
						rr.ttl = m_ttl;

						if( qt.getCode() == QType::MX || qt.getCode() == QType::SRV )   // Priority, e.g. 10 smtp.example.com
						{
							char* endptr;
							string::size_type first = content.find_first_of( " " );

							if( first == string::npos )
							{
								L << Logger::Warning << backendname << " Invalid " << attrname << " without priority for " << m_qname << ": " << content << endl;
								m_value++;
								continue;
							}

							rr.priority = (u_int16_t) strtoul( (content.substr( 0, first )).c_str(), &endptr, 10 );
							if( *endptr != '\0' )
							{
								L << Logger::Warning << backendname << " Invalid " << attrname << " without priority for " << m_qname << ": " << content << endl;
								m_value++;
								continue;
							}

							content = content.substr( first + 1, content.length() - first - 1 );
						}

						rr.content = content;
						m_value++;

						DLOG( L << Logger::Debug << backendname << " Record = qname: " << rr.qname << ", qtype: " << (rr.qtype).getName() << ", priority: " << rr.priority << ", ttl: " << rr.ttl << ", content: " << rr.content << endl );
						return true;
					}

					m_attribute++;
					m_value = m_attribute->second.begin();
				}
				m_adomain++;
				m_attribute = m_result.begin();
				m_value = m_attribute->second.begin();
			}
		}
		while( m_pldap->getSearchEntry( m_msgid, m_result, false ) && prepareEntry() );

	}
	catch( LDAPTimeout &lt )
	{
		L << Logger::Warning << backendname << " Search failed: " << lt.what() << endl;
	}
	catch( LDAPException &le )
	{
		L << Logger::Error << backendname << " Search failed: " << le.what() << endl;
		throw( AhuException( "LDAP server unreachable" ) );   // try to reconnect to another server
	}
	catch( exception &e )
	{
		L << Logger::Error << backendname << " Caught STL exception for attribute " << attrname << ": " << e.what() << endl;
	}
	catch( ... )
	{
		L << Logger::Critical << backendname << " Caught unknown exception for attribute " << attrname << endl;
	}

	return false;
}


inline bool LdapBackend::prepareEntry()
{
	m_adomains.clear();
	m_ttl = m_default_ttl;

	if( m_result.count( "dNSTTL" ) && !m_result["dNSTTL"].empty() )
	{
		m_ttl = (u_int32_t) strtol( m_result["dNSTTL"][0].c_str(), NULL, 10 );
		m_result.erase( "dNSTTL" );
	}

	if( !m_axfrqlen )   // request was a normal lookup()
	{
		m_adomains.push_back( m_qname );
		if( m_result.count( "associatedDomain" ) )
		{
			m_result["PTRRecord"] = m_result["associatedDomain"];
			m_result.erase( "associatedDomain" );
		}
	}
	else   // request was a list() for AXFR
	{
		if( m_result.count( "associatedDomain" ) )
		{
			vector<string>::iterator i;
			for( i = m_result["associatedDomain"].begin(); i != m_result["associatedDomain"].end(); i++ ) {
				if( i->substr( i->length() - m_axfrqlen, m_axfrqlen ) == m_qname ) {
					m_adomains.push_back( *i );
				}
			}
			m_result.erase( "associatedDomain" );
		}
	}

	m_adomain = m_adomains.begin();
	m_attribute = m_result.begin();
	m_value = m_attribute->second.begin();

	return true;
}


class LdapFactory : public BackendFactory
{

public:

	LdapFactory() : BackendFactory( "ldap" ) {}

	void declareArguments( const string &suffix="" )
	{
		declare( suffix, "host", "one or more ldap server","localhost:389" );
		declare( suffix, "port", "ldap server port (depricated, use ldap-host)","389" );
		declare( suffix, "starttls", "use TLS to encrypt connection", "no" );
		declare( suffix, "basedn", "search root in ldap tree (must be set)","" );
		declare( suffix, "binddn", "user dn for non anonymous binds","" );
		declare( suffix, "secret", "user password for non anonymous binds", "" );
		declare( suffix, "disable-ptrrecord", "disable necessity for seperate PTR records", "no" );
		declare( suffix, "default-ttl", "default ttl if DNSTTL is not set (depricated, use default-ttl)", "3600" );
	}


	DNSBackend* make( const string &suffix="" )
	{
		return new LdapBackend( suffix );
	}
};




class Loader
{

public:

	Loader()
	{
		BackendMakers().report( new LdapFactory );
		L << Logger::Info << backendname << " This is the ldap module version "VERSION" ("__DATE__", "__TIME__") reporting" << endl;
  }
};


static Loader loader;
