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



static int Toupper(int c)
{
  return toupper(c);
}


LdapBackend::LdapBackend( const string &suffix )
{
	m_msgid = 0;
	m_qname = "";
	setArgPrefix( "ldap" + suffix );


	m_default_ttl = (u_int32_t) strtol( getArg( "default-ttl" ).c_str(), NULL, 10 );

	try
	{
		L << Logger::Info << backendname << " LDAP Server = " << getArg( "host" ) << ":" << getArg( "port" ) << endl;
		m_pldap = new PowerLDAP( getArg( "host" ), (u_int16_t) atoi( getArg( "port" ).c_str() ) );
		m_pldap->simpleBind( getArg( "binddn" ), getArg( "secret" ) );
	}
	catch( LDAPException &e )
	{
		delete( m_pldap );
		L << Logger::Error << backendname << " Ldap connection failed: " << e.what() << endl;
		throw( AhuException( "Unable to bind to ldap server" ) );
	}

	L << Logger::Info << backendname << " Ldap connection succeeded" << endl;
}


LdapBackend::~LdapBackend()
{
	delete( m_pldap );
	L << Logger::Notice << backendname << " Ldap connection closed" << endl;
}


bool LdapBackend::list( const string &target, int domain_id )
{
	string filter, dn;
	char* attributes[] = { "associatedDomain", NULL };


	try
	{
		L << Logger::Notice << backendname << " AXFR request for " << target << endl;

		// search for DN of SOA record which is SOA for target zone

		filter = "(&(associatedDomain=" + target + ")(SOARecord=*))";
		m_msgid = m_pldap->search( getArg("basedn"), LDAP_SCOPE_SUBTREE, filter, (const char**) attributes );

		if( m_pldap->getSearchEntry( m_msgid, m_result, true ) == false )
		{
			L << Logger::Error << backendname << " Unable to get SOA record for " << target << endl;
			return false;
		}

		if( m_result.empty() )
		{
			L << Logger::Error << backendname << " No SOA record for " << target << endl;
			return false;
		}

		if( m_result.find( "dn" ) == m_result.end() )
		{
			L << Logger::Error << backendname << " LDAP error while searching SOA record for " << target << endl;
			return false;
		}

		if( m_result["dn"].empty() )
		{
			L << Logger::Error << backendname << " LDAP error while getting SOA record for " << target << endl;
			return false;
		}

		dn = m_result["dn"].front();
		m_result.clear();

		// list all records one level below but not entries containing SOA records (these are seperate zones)

		m_qname = "";
		m_adomain = m_adomains.end();   // skip loops in get() first time
		filter = "(&(associatedDomain=*)(!(SOARecord=*)))";
		m_msgid = m_pldap->search( dn, LDAP_SCOPE_ONELEVEL, filter, (const char**) attrany );
	}
	catch( LDAPException &le )
	{
		L << Logger::Error << backendname << " Unable to get zone " + target + " from LDAP directory: " << le.what() << endl;
		return false;
	}
	catch( exception &e )
	{
		L << Logger::Error << backendname << " Caught STL exception: " << e.what() << endl;
		return false;
	}
	catch( ... )
	{
		L << Logger::Critical << backendname << " Caught unknown exception" << endl;
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
		m_qtype = qtype;
		m_qname = qname;
		qesc = m_pldap->escape( qname );

		if( mustDo( "disable-ptrrecord" ) )  // PTRRecords will be derived from ARecords
		{
			len = qesc.length();
			stringtok( parts, qesc, "." );

			 if( len > 13 && qesc.substr( len - 13, 13 ) == ".in-addr.arpa" )   // IPv4 reverse lookups
			{
				parts.pop_back();
				parts.pop_back();

				filter = "(aRecord=" + parts.back();
				parts.pop_back();
				while( !parts.empty() )
				{
					filter += "." + parts.back();
					parts.pop_back();
				}
				filter += ")";

				attronly[0] = "associatedDomain";
				attributes = attronly;
			}
			else if( len > 9 && ( qesc.substr( len - 8, 8 ) == ".ip6.int" || qesc.substr( len - 9, 9 ) == ".ip6.arpa" ) )   // IPv6 reverse lookups
			{
				parts.pop_back();
				parts.pop_back();

				filter = "(aAAARecord=" + parts.back();
				parts.pop_back();
				while( !parts.empty() )
				{
					filter += ":" + parts.back();
					parts.pop_back();
				}
				filter += ")";

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

		m_adomain = m_adomains.end();   // skip loops in get() first time
		L << Logger::Info << backendname << " Search = basedn: " << getArg( "basedn" ) << ", filter: " << filter << ", qtype: " << qtype.getName() << endl;
		m_msgid = m_pldap->search( getArg("basedn"), LDAP_SCOPE_SUBTREE, filter, (const char**) attributes );
	}
	catch( LDAPException &le )
	{
		L << Logger::Warning << backendname << " Unable to search LDAP directory: " << le.what() << endl;
		return;
	}
	catch( exception &e )
	{
		L << Logger::Error << backendname << " Caught STL exception: " << e.what() << endl;
		return;
	}
	catch( ... )
	{
		L << Logger::Error << backendname << " Caught unknown exception" << endl;
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
			do
			{
				while( m_adomain != m_adomains.end() )
				{
					while( m_attribute != m_result.end() )
					{
						attrname = m_attribute->first;
						qstr = attrname.substr( 0, attrname.length() - 6 );   // extract qtype string from ldap attribute name
						transform( qstr.begin(), qstr.end(), qstr.begin(), &Toupper );
						qt = QType( const_cast<char*>(qstr.c_str()) );

						while( m_value != m_attribute->second.end() )
						{
							content = *m_value;

							rr.qtype = qt;
							rr.qname = *m_adomain;
							rr.priority = 0;
							rr.ttl = m_ttl;

							if( qt.getCode() == QType::MX )   // MX Record, e.g. 10 smtp.example.com
							{
								parts.clear();
								stringtok( parts, content, " " );

								if( parts.size() != 2)
								{
									L << Logger::Warning << backendname << " Invalid MX record without priority: " << content << endl;
									continue;
								}

								rr.priority = (u_int16_t) strtol( parts[0].c_str(), NULL, 10 );
								content = parts[1];
							}

							rr.content = content;
							m_value++;

							L << Logger::Info << backendname << " Record = qname: " << rr.qname << ", qtype: " << (rr.qtype).getName() << ", priority: " << rr.priority << ", content: " << rr.content << endl;
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
			while( !m_adomains.empty() && m_qname.empty() && mustDo( "disable-ptrrecord" ) && makePtrRecords() );   // make PTR records from associatedDomain entries

			m_result.clear();
		}
		while( m_pldap->getSearchEntry( m_msgid, m_result, false ) && prepSearchEntry() );

	}
	catch( LDAPException &le )
	{
		L << Logger::Warning << backendname << " Search failed: " << le.what() << endl;
	}
	catch( exception &e )
	{
		L << Logger::Error << backendname << " Caught STL exception: " << e.what() << endl;
	}
	catch( ... )
	{
		L << Logger::Error << backendname << " Caught unknown exception" << endl;
	}

	return false;
}


inline bool LdapBackend::prepSearchEntry()
{
	m_adomains.clear();
	m_ttl = m_default_ttl;

	if( m_result.find( "dNSTTL" ) != m_result.end() && !m_result["dNSTTL"].empty() )
	{
		m_ttl = (u_int32_t) strtol( m_result["dNSTTL"][0].c_str(), NULL, 10 );
		m_result.erase( "dNSTTL" );
	}

	if( !m_qname.empty() )   // request was a normal lookup()
	{
		m_adomains.push_back( m_qname );
		if( m_result.find( "associatedDomain" ) != m_result.end() )
		{
			m_result["PTRRecord"] = m_result["associatedDomain"];
			m_result.erase( "associatedDomain" );
		}
	}
	else   // request was a list() for AXFR
	{
		if( m_result.find( "associatedDomain" ) != m_result.end() )
		{
			m_adomains = m_result["associatedDomain"];
			m_result.erase( "associatedDomain" );
		}
	}

	m_adomain = m_adomains.begin();
	m_attribute = m_result.begin();
	m_value = m_attribute->second.begin();

	return true;
}


inline bool LdapBackend::makePtrRecords()
{
	unsigned int i = 0;
	string ptrsrc;
	vector<string> parts, tmp;
	vector<string>::iterator record;
	char* attr[] = { "aRecord", "aAAARecord", NULL };
	char* suffix[] = { ".in-addr.arpa", ".ip6.int", NULL };
	char* seperator[] = { ".", ":", NULL };


	tmp = m_adomains;
	m_adomains.clear();

	while( attr[i] != NULL && m_result.find( attr[i] ) != m_result.end() )
	{
		for( record = m_result[attr[i]].begin(); record != m_result[attr[i]].end(); record++ )
		{
			parts.clear();
			stringtok( parts, *record, seperator[i] );

			ptrsrc = parts.back();
			parts.pop_back();
			while( !parts.empty() )
			{
				ptrsrc += "." + parts.back();
				parts.pop_back();
			}
			ptrsrc += suffix[i];

			m_adomains.push_back( ptrsrc );
		}

		i++;
	}

	if( m_adomains.empty() )
	{
		return false;
	}

	m_result.clear();
	m_result["PTRRecord"] = tmp;
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
		declare( suffix, "host", "your ldap server","localhost" );
		declare( suffix, "port", "ldap server port","389" );
		declare( suffix, "basedn", "search root in ldap tree (must be set)","" );
		declare( suffix, "binddn", "user dn for non anonymous binds","" );
		declare( suffix, "secret", "user password for non anonymous binds", "" );
		declare( suffix, "disable-ptrrecord", "disable necessity for seperate PTR records", "no" );
		declare( suffix, "default-ttl", "default ttl if DNSTTL is not set", "86400" );
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
		L << Logger::Notice << backendname << " This is the ldap module version "VERSION" ("__DATE__", "__TIME__") reporting" << endl;
  }
};


static Loader loader;
