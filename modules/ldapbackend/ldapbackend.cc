#include "ldapbackend.hh"

#include <utility>

static int Toupper(int c)
{
  return toupper(c);
}


LdapBackend::LdapBackend( const string &suffix )
{
	m_msgid = 0;
	m_qname = "";
	setArgPrefix( "ldap" + suffix );

	L << Logger::Notice << backendname << " Server = " << getArg( "host" ) << ":" << getArg( "port" ) << endl;

	try
	{
	m_pldap = new PowerLDAP( getArg( "host" ), (u_int16_t) atoi( getArg( "port" ).c_str() ) );
	m_pldap->simpleBind( getArg( "binddn" ), getArg( "secret" ) );
	}
	catch( LDAPException &e )
	{
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
	int i, len;
	vector<string> parts;
	string filter, attr, ipaddr;
	char** attributes = attrany;
	char* attronly[] = { NULL, NULL };


	m_qtype = qtype;
	m_qname = qname;
	len = qname.length();

	if( qname.substr( len - 5, 5 ) == ".arpa" || qname.substr( len - 4, 4 ) == ".int" )
	{
		stringtok( parts, qname, "." );
		if (parts[parts.size()-2] == "ip6" )
		{
			filter = "(aaaaRecord=" + parts[parts.size()-3];
			for( i = parts.size() - 4; i >= 0; i-- )   // reverse and cut .ip6.arpa or .ip6.int
			{
				  filter += ":" + parts[i];
			}
			filter =  + ")";
		}
		else
	{
		filter = "(aRecord=" + parts[3] + "." + parts[2] + "." + parts[1] + "." + parts[0] + ")";
		}

		filter = m_pldap->escape( filter );
		attronly[0] = "associatedDomain";
		attributes = attronly;
	}
	else
	{
		filter = "(associatedDomain=" + m_pldap->escape( m_qname ) + ")";
	if( qtype.getCode() != QType::ANY )
	{
		attr = qtype.getName() + "Record";
		filter = "(&" + filter + "(" + attr + "=*))";
			attronly[0] = (char*) attr.c_str();
		attributes = attronly;
	}
	}

	try
	{
	m_msgid = m_pldap->search( getArg("basedn"), filter, (const char**) attributes );
	}
	catch( LDAPException &e )
	{
		L << Logger::Warning << backendname << " Unable to initiate search: " << e.what() << endl;
		return;
	}

	L << Logger::Info << backendname << " Search = basedn: " << getArg( "basedn" ) << ", filter: " << filter << ", qtype: " << qtype.getName() << endl;
}


bool LdapBackend::get( DNSResourceRecord &rr )
{
	QType qt;
	vector<string> parts;
	vector<string> values;
	string attrname, content, qstr;
	PowerLDAP::sentry_t::iterator attribute;


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

				if( qt.getCode() == QType::MX )   // MX Record, e.g. 10 smtp.example.com
  				{
					stringtok( parts, content, " " );
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

	try
	{
		if( m_pldap->getSearchEntry( m_msgid, m_result ) == true )
		{
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

	return false;
}




class LdapFactory : public BackendFactory
{

public:

	LdapFactory() : BackendFactory( "ldap" ) {}

	void declareArguments( const string &suffix="" )
	{
		declare( suffix, "host", "ldap server","localhost" );
		declare( suffix, "port", "server port","389" );
		declare( suffix, "basedn", "search root","" );
		declare( suffix, "binddn", "user dn","" );
		declare( suffix, "secret", "user password", "" );
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
