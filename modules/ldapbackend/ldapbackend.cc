#include "ldapbackend.hh"

#include <algorithm>
#include <utility>
#include <ctype.h> 

static int Toupper(int c)
{
  return toupper(c);
}


LdapBackend::LdapBackend( const string &suffix )
{
	m_msgid = 0;
	m_qname = "";
	m_revlookup = 0;
	setArgPrefix( "ldap" + suffix );

	L << Logger::Notice << backendname << " Server = " << getArg( "host" ) << ":" << getArg( "port" ) << endl;

	// Initialize connections and pass exeptions to caller
	m_pldap = new PowerLDAP( getArg( "host" ), (u_int16_t) atoi( getArg( "port" ).c_str() ) );
	m_pldap->simpleBind( getArg( "binddn" ), getArg( "secret" ) );

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
	int len = 0;
	vector<string> parts;
	string filter, attr, ipaddr;
	char** attributes = attrany;
	char* attronly[] = { "associatedDomain", NULL, NULL };


	m_qtype = qtype;
	m_qname = qname;
	len = qname.length();

	if( len > 20 && qname.substr( len - 13, 13 ) == ".in-addr.arpa" )
	{
		m_revlookup = 1;
		stringtok( parts, qname.substr( 0, len - 13 ), "." );
		filter = "(aRecord=" + parts[3] + "." + parts[2] + "." + parts[1] + "." + parts[0] + ")";
		attributes = attronly;
	}
	else
	{
		m_revlookup = 0;
		filter = "(associatedDomain=" + m_pldap->escape( m_qname ) + ")";
	}

	if( qtype.getCode() != QType::ANY )
	{
		attr = qtype.getName() + "Record";
		filter = "(&" + filter + "(" + attr + "=*))";
		attronly[1] = (char*) attr.c_str();
		attributes = attronly;
	}

	// Pass exception if an error occurs
	m_msgid = m_pldap->search( getArg("basedn"), filter, (const char**) attributes );
	L << Logger::Info << backendname << " Search = basedn: " << getArg( "basedn" ) << ", filter: " << filter << ", qtype: " << qtype.getName() << endl;
}


bool LdapBackend::get( DNSResourceRecord &rr )
{
	QType qt;
	vector<string> parts;
	vector<string> values;
	string attrname, content, qstr;
	PowerLDAP::sentry_t::iterator attribute;


	do
	{
		while( !m_result.empty() )
		{
			if( m_revlookup == 1 && m_result.find( "associatedDomain" ) != m_result.end() )
			{
				m_result["PTRRecord"] = m_result["associatedDomain"];
			}
			m_result.erase( "associatedDomain" );

			attribute = m_result.begin();
			attrname = attribute->first;
			qstr = attrname.substr( 0, attrname.length() - 6 );   // extract qtype string from ldap attribute name
			transform( qstr.begin(), qstr.end(), qstr.begin(), &Toupper );
			qt = QType( const_cast<char*>(qstr.c_str()) );

			while( !attribute->second.empty() && ( m_qtype.getCode() == QType::ANY ||  m_qtype.getCode() == qt.getCode() ) )
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
			m_result.erase( attribute );
		}
	}
	while( m_pldap->getSearchEntry( m_msgid, m_result ) );

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
