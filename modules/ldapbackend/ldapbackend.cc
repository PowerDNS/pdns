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

	L << Logger::Notice << backendname << " LDAP Server = " << getArg( "host" ) << ":" << getArg( "port" ) << endl;

	try
	{
		m_pldap = new PowerLDAP( getArg( "host" ), (u_int16_t) atoi( getArg( "port" ).c_str() ) );
		m_pldap->simpleBind( getArg( "binddn" ), getArg( "secret" ) );
	}
	catch( LDAPException &e )
	{
		delete( m_pldap );
		L << Logger::Error << backendname << " Ldap connection failed: " << e.what() << endl;
		throw( AhuException( "Unable to bind to ldap server" ) );
	}

	L << Logger::Notice << backendname << " Ldap connection succeeded" << endl;
}


LdapBackend::~LdapBackend()
{
	delete( m_pldap );
	L << Logger::Notice << backendname << " Ldap connection closed" << endl;
}


bool LdapBackend::list( int domain_id )
{
	L << Logger::Warning << backendname << " AXFR is not supported" << endl;
	return false;
}


void LdapBackend::lookup( const QType &qtype, const string &qname, DNSPacket *dnspkt, int zoneid )
{
	int len;
	vector<string> parts;
	string filter, attr, qesc;
	char** attributes = attrany;
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

			if( len > 9 && ( qesc.substr( len - 9, 9 ) == ".ip6.arpa" || qesc.substr( len - 8, 8 ) == ".ip6.int" ) )   // IPv6 reverse lookups
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
			else if( len > 13 && qesc.substr( len - 13, 13 ) == ".in-addr.arpa" )   // IPv4 reverse lookups
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

		L << Logger::Info << backendname << " Search = basedn: " << getArg( "basedn" ) << ", filter: " << filter << ", qtype: " << qtype.getName() << endl;
		m_msgid = m_pldap->search( getArg("basedn"), filter, (const char**) attributes );
	}
	catch( LDAPException &e )
	{
		L << Logger::Warning << backendname << " Unable to search LDAP directory: " << e.what() << endl;
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
	vector<string> values;
	string attrname, content, qstr;
	PowerLDAP::sentry_t::iterator attribute;


	try
	{

Redo:

		while( !m_result.empty() )
		{
			attribute = m_result.begin();
			if( attribute != m_result.end() && !attribute->second.empty() )
			{
				attrname = attribute->first;
				qstr = attrname.substr( 0, attrname.length() - 6 );   // extract qtype string from ldap attribute name
				transform( qstr.begin(), qstr.end(), qstr.begin(), &Toupper );
				qt = QType( const_cast<char*>(qstr.c_str()) );

				if( m_qtype.getCode() == QType::ANY ||  m_qtype.getCode() == qt.getCode() )
				{
					content = attribute->second.back();
					attribute->second.pop_back();

					rr.qtype = qt;
					rr.qname = m_qname;
					rr.priority = 0;
					rr.ttl = m_ttl;

					if( qt.getCode() == QType::MX )   // MX Record, e.g. 10 smtp.example.com
					{
						parts.clear();
						stringtok( parts, content, " " );

						if( parts.size() != 2)
						{
							L << Logger::Warning << backendname << " Invalid MX record without priority: " << content << endl;
							goto Redo;
						}

						rr.priority = (u_int16_t) strtol( parts[0].c_str(), NULL, 10 );
						content = parts[1];
					}
					rr.content = content;

					L << Logger::Info << backendname << " Record = qname: " << rr.qname << ", qtype: " << (rr.qtype).getName() << ", priority: " << rr.priority << ", content: " << rr.content << endl;
					return true;
				}
			}
			m_result.erase( attribute );
		}

		if( m_pldap->getSearchEntry( m_msgid, m_result ) == true )
		{
				if( m_result.find( "dNSTTL" ) != m_result.end() && m_result["dNSTTL"].size() > 0 )
				{
					m_ttl = (u_int32_t) strtol( m_result["dNSTTL"][0].c_str(), NULL, 10 );
					m_result.erase( "dNSTTL" );
				}
				else
				{
					m_ttl = (u_int32_t) strtol( getArg( "default-ttl" ).c_str(), NULL, 10 );
				}

				if( m_result.find( "associatedDomain" ) != m_result.end() )
				{
					m_result["PTRRecord"] = m_result["associatedDomain"];
					m_result.erase( "associatedDomain" );
				}

				goto Redo;
		}
	}
	catch( LDAPException &e )
	{
		L << Logger::Warning << backendname << " Search failed: " << e.what() << endl;
	}
	catch( ... )
	{
		L << Logger::Error << backendname << " Caught unknown exception" << endl;
	}

	return false;
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
