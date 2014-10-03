#include "ldapbackend.hh"



unsigned int ldap_host_index = 0;



LdapBackend::LdapBackend( const string &suffix )
{
        string hoststr;
        unsigned int i, idx;
        vector<string> hosts;


        try
        {
        	m_msgid = 0;
        	m_qname = "";
        	m_pldap = NULL;
        	m_qlog = arg().mustDo( "query-logging" );
        	m_default_ttl = arg().asNum( "default-ttl" );
        	m_myname = "[LdapBackend]";

        	setArgPrefix( "ldap" + suffix );

        	m_getdn = false;
        	m_list_fcnt = &LdapBackend::list_simple;
        	m_lookup_fcnt = &LdapBackend::lookup_simple;
        	m_prepare_fcnt = &LdapBackend::prepare_simple;

        	if( getArg( "method" ) == "tree" )
        	{
        		m_lookup_fcnt = &LdapBackend::lookup_tree;
        	}

        	if( getArg( "method" ) == "strict" || mustDo( "disable-ptrrecord" ) )
        	{
        		m_list_fcnt = &LdapBackend::list_strict;
        		m_lookup_fcnt = &LdapBackend::lookup_strict;
        		m_prepare_fcnt = &LdapBackend::prepare_strict;
        	}

        	stringtok( hosts, getArg( "host" ), ", " );
        	idx = ldap_host_index++ % hosts.size();
        	hoststr = hosts[idx];

        	for( i = 1; i < hosts.size(); i++ )
        	{
        		hoststr += " " + hosts[ ( idx + i ) % hosts.size() ];
        	}

        	L << Logger::Info << m_myname << " LDAP servers = " << hoststr << endl;

        	m_pldap = new PowerLDAP( hoststr.c_str(), LDAP_PORT, mustDo( "starttls" ) );
        	m_pldap->setOption( LDAP_OPT_DEREF, LDAP_DEREF_ALWAYS );
        	m_pldap->bind( getArg( "binddn" ), getArg( "secret" ), LDAP_AUTH_SIMPLE, getArgAsNum( "timeout" ) );

        	L << Logger::Notice << m_myname << " Ldap connection succeeded" << endl;
        	return;
        }
        catch( LDAPTimeout &lt )
        {
        	L << Logger::Error << m_myname << " Ldap connection to server failed because of timeout" << endl;
        }
        catch( LDAPException &le )
        {
        	L << Logger::Error << m_myname << " Ldap connection to server failed: " << le.what() << endl;
        }
        catch( std::exception &e )
        {
        	L << Logger::Error << m_myname << " Caught STL exception: " << e.what() << endl;
        }

        if( m_pldap != NULL ) { delete( m_pldap ); }
        throw( PDNSException( "Unable to connect to ldap server" ) );
}



LdapBackend::~LdapBackend()
{
        if( m_pldap != NULL ) { delete( m_pldap ); }
        L << Logger::Notice << m_myname << " Ldap connection closed" << endl;
}



bool LdapBackend::list( const string& target, int domain_id, bool include_disabled )
{
        try
        {
        	m_qname = target;
        	m_axfrqlen = target.length();
        	m_adomain = m_adomains.end();   // skip loops in get() first time

        	return (this->*m_list_fcnt)( target, domain_id );
        }
        catch( LDAPTimeout &lt )
        {
        	L << Logger::Warning << m_myname << " Unable to get zone " + target + " from LDAP directory: " << lt.what() << endl;
        	throw( DBException( "LDAP server timeout" ) );
        }
        catch( LDAPException &le )
        {
        	L << Logger::Error << m_myname << " Unable to get zone " + target + " from LDAP directory: " << le.what() << endl;
        	throw( PDNSException( "LDAP server unreachable" ) );   // try to reconnect to another server
        }
        catch( std::exception &e )
        {
        	L << Logger::Error << m_myname << " Caught STL exception for target " << target << ": " << e.what() << endl;
        	throw( DBException( "STL exception" ) );
        }

        return false;
}



inline bool LdapBackend::list_simple( const string& target, int domain_id )
{
        string dn;
        string filter;
    string qesc;


        dn = getArg( "basedn" );
        qesc = toLower( m_pldap->escape( target ) );

        // search for SOARecord of target
        filter = strbind( ":target:", "&(associatedDomain=" + qesc + ")(sOARecord=*)", getArg( "filter-axfr" ) );
        m_msgid = m_pldap->search( dn, LDAP_SCOPE_SUBTREE, filter, (const char**) ldap_attrany );
        m_pldap->getSearchEntry( m_msgid, m_result, true );

        if( m_result.count( "dn" ) && !m_result["dn"].empty() )
        {
		if( !mustDo( "basedn-axfr-override" ) )
		{
			dn = m_result["dn"][0];
		}
        	m_result.erase( "dn" );
        }

        prepare();
        filter = strbind( ":target:", "associatedDomain=*." + qesc, getArg( "filter-axfr" ) );
        DLOG( L << Logger::Debug << m_myname << " Search = basedn: " << dn << ", filter: " << filter << endl );
        m_msgid = m_pldap->search( dn, LDAP_SCOPE_SUBTREE, filter, (const char**) ldap_attrany );

        return true;
}



inline bool LdapBackend::list_strict( const string& target, int domain_id )
{
        if( (target.size() > 13 && target.substr( target.size() - 13, 13 ) == ".in-addr.arpa") ||
        	(target.size() > 9 && target.substr( target.size() - 9, 9 ) == ".ip6.arpa") )
        {
        	L << Logger::Warning << m_myname << " Request for reverse zone AXFR, but this is not supported in strict mode" << endl;
        	return false;   // AXFR isn't supported in strict mode. Use simple mode and additional PTR records
        }

        return list_simple( target, domain_id );
}



void LdapBackend::lookup( const QType &qtype, const string &qname, DNSPacket *dnspkt, int zoneid )
{
        try
        {
        	m_axfrqlen = 0;
        	m_qname = qname;
        	m_adomain = m_adomains.end();   // skip loops in get() first time

        	if( m_qlog ) { L.log( "Query: '" + qname + "|" + qtype.getName() + "'", Logger::Error ); }
        	(this->*m_lookup_fcnt)( qtype, qname, dnspkt, zoneid );
        }
        catch( LDAPTimeout &lt )
        {
        	L << Logger::Warning << m_myname << " Unable to search LDAP directory: " << lt.what() << endl;
        	throw( DBException( "LDAP server timeout" ) );
        }
        catch( LDAPException &le )
        {
        	L << Logger::Error << m_myname << " Unable to search LDAP directory: " << le.what() << endl;
        	throw( PDNSException( "LDAP server unreachable" ) );   // try to reconnect to another server
        }
        catch( std::exception &e )
        {
        	L << Logger::Error << m_myname << " Caught STL exception for qname " << qname << ": " << e.what() << endl;
        	throw( DBException( "STL exception" ) );
        }
}



void LdapBackend::lookup_simple( const QType &qtype, const string &qname, DNSPacket *dnspkt, int zoneid )
{
        string filter, attr, qesc;
        const char** attributes = ldap_attrany + 1;   // skip associatedDomain
        const char* attronly[] = { NULL, "dNSTTL", "modifyTimestamp", NULL };


        qesc = toLower( m_pldap->escape( qname ) );
        filter = "associatedDomain=" + qesc;

        if( qtype.getCode() != QType::ANY )
        {
        	attr = qtype.getName() + "Record";
        	filter = "&(" + filter + ")(" + attr + "=*)";
        	attronly[0] = attr.c_str();
        	attributes = attronly;
        }

        filter = strbind( ":target:", filter, getArg( "filter-lookup" ) );

        DLOG( L << Logger::Debug << m_myname << " Search = basedn: " << getArg( "basedn" ) << ", filter: " << filter << ", qtype: " << qtype.getName() << endl );
        m_msgid = m_pldap->search( getArg( "basedn" ), LDAP_SCOPE_SUBTREE, filter, attributes );
}



void LdapBackend::lookup_strict( const QType &qtype, const string &qname, DNSPacket *dnspkt, int zoneid )
{
        int len;
        vector<string> parts;
        string filter, attr, qesc;
        const char** attributes = ldap_attrany + 1;   // skip associatedDomain
        const char* attronly[] = { NULL, "dNSTTL", "modifyTimestamp", NULL };


        qesc = toLower( m_pldap->escape( qname ) );
        stringtok( parts, qesc, "." );
        len = qesc.length();

         if( parts.size() == 6 && len > 13 && qesc.substr( len - 13, 13 ) == ".in-addr.arpa" )   // IPv4 reverse lookups
        {
        	filter = "aRecord=" + ptr2ip4( parts );
        	attronly[0] = "associatedDomain";
        	attributes = attronly;
        }
        else if( parts.size() == 34 && len > 9 && ( qesc.substr( len - 9, 9 ) == ".ip6.arpa" ) )   // IPv6 reverse lookups
        {
        	filter = "aAAARecord=" + ptr2ip6( parts );
        	attronly[0] = "associatedDomain";
        	attributes = attronly;
        }
        else   // IPv4 and IPv6 lookups
        {
        	filter = "associatedDomain=" + qesc;
        	if( qtype.getCode() != QType::ANY )
        	{
        		attr = qtype.getName() + "Record";
        		filter = "&(" + filter + ")(" + attr + "=*)";
        		attronly[0] = attr.c_str();
        		attributes = attronly;
        	}
        }

        filter = strbind( ":target:", filter, getArg( "filter-lookup" ) );

        DLOG( L << Logger::Debug << m_myname << " Search = basedn: " << getArg( "basedn" ) << ", filter: " << filter << ", qtype: " << qtype.getName() << endl );
        m_msgid = m_pldap->search( getArg( "basedn" ), LDAP_SCOPE_SUBTREE, filter, attributes );
}



void LdapBackend::lookup_tree( const QType &qtype, const string &qname, DNSPacket *dnspkt, int zoneid )
{
        string filter, attr, qesc, dn;
        const char** attributes = ldap_attrany + 1;   // skip associatedDomain
        const char* attronly[] = { NULL, "dNSTTL", "modifyTimestamp", NULL };
        vector<string>::reverse_iterator i;
        vector<string> parts;


        qesc = toLower( m_pldap->escape( qname ) );
        filter = "associatedDomain=" + qesc;

        if( qtype.getCode() != QType::ANY )
        {
        	attr = qtype.getName() + "Record";
        	filter = "&(" + filter + ")(" + attr + "=*)";
        	attronly[0] = attr.c_str();
        	attributes = attronly;
        }

        filter = strbind( ":target:", filter, getArg( "filter-lookup" ) );

        stringtok( parts, toLower( qname ), "." );
        for( i = parts.rbegin(); i != parts.rend(); i++ )
        {
        	dn = "dc=" + *i + "," + dn;
        }

        DLOG( L << Logger::Debug << m_myname << " Search = basedn: " << dn + getArg( "basedn" ) << ", filter: " << filter << ", qtype: " << qtype.getName() << endl );
        m_msgid = m_pldap->search( dn + getArg( "basedn" ), LDAP_SCOPE_BASE, filter, attributes );
}


inline bool LdapBackend::prepare()
{
        m_adomains.clear();
        m_ttl = m_default_ttl;
        m_last_modified = 0;

        if( m_result.count( "dNSTTL" ) && !m_result["dNSTTL"].empty() )
        {
        	char* endptr;

        	m_ttl = (uint32_t) strtol( m_result["dNSTTL"][0].c_str(), &endptr, 10 );
        	if( *endptr != '\0' )
        	{
        		L << Logger::Warning << m_myname << " Invalid time to life for " << m_qname << ": " << m_result["dNSTTL"][0] << endl;
        		m_ttl = m_default_ttl;
        	}
        	m_result.erase( "dNSTTL" );
        }

        if( m_result.count( "modifyTimestamp" ) && !m_result["modifyTimestamp"].empty() )
        {
        	if( ( m_last_modified = str2tstamp( m_result["modifyTimestamp"][0] ) ) == 0 )
        	{
        		L << Logger::Warning << m_myname << " Invalid modifyTimestamp for " << m_qname << ": " << m_result["modifyTimestamp"][0] << endl;
        	}
        	m_result.erase( "modifyTimestamp" );
        }

        if( !(this->*m_prepare_fcnt)() )
        {
        	return false;
        }

        m_adomain = m_adomains.begin();
        m_attribute = m_result.begin();
        m_value = m_attribute->second.begin();

        return true;
}



inline bool LdapBackend::prepare_simple()
{
        if( !m_axfrqlen )   // request was a normal lookup()
        {
        	m_adomains.push_back( m_qname );
        }
        else   // request was a list() for AXFR
        {
        	if( m_result.count( "associatedDomain" ) )
        	{
        		vector<string>::iterator i;
        		for( i = m_result["associatedDomain"].begin(); i != m_result["associatedDomain"].end(); i++ ) {
        			if( i->size() >= m_axfrqlen && i->substr( i->size() - m_axfrqlen, m_axfrqlen ) == m_qname ) {
        				m_adomains.push_back( *i );
        			}
        		}
        		m_result.erase( "associatedDomain" );
        	}
        }

        return true;
}



inline bool LdapBackend::prepare_strict()
{
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
        			if( i->size() >= m_axfrqlen && i->substr( i->size() - m_axfrqlen, m_axfrqlen ) == m_qname ) {
        				m_adomains.push_back( *i );
        			}
        		}
        		m_result.erase( "associatedDomain" );
        	}
        }

        return true;
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
        				qt = const_cast<char*>(toUpper( qstr ).c_str());

        				while( m_value != m_attribute->second.end() )
        				{
        					content = *m_value;

        					rr.qtype = qt;
        					rr.qname = *m_adomain;
        					rr.priority = 0;
        					rr.ttl = m_ttl;
        					rr.last_modified = m_last_modified;

        					if( qt.getCode() == QType::MX || qt.getCode() == QType::SRV )   // Priority, e.g. 10 smtp.example.com
        					{
        						char* endptr;
        						string::size_type first = content.find_first_of( " " );

        						if( first == string::npos )
        						{
        							L << Logger::Warning << m_myname << " Invalid " << attrname << " without priority for " << m_qname << ": " << content << endl;
        							m_value++;
        							continue;
        						}

        						rr.priority = (uint16_t) strtoul( (content.substr( 0, first )).c_str(), &endptr, 10 );
        						if( *endptr != '\0' )
        						{
        							L << Logger::Warning << m_myname << " Invalid " << attrname << " without priority for " << m_qname << ": " << content << endl;
        							m_value++;
        							continue;
        						}

        						content = content.substr( first + 1, content.length() - first - 1 );
        					}

        					rr.content = content;
        					m_value++;

        					DLOG( L << Logger::Debug << m_myname << " Record = qname: " << rr.qname << ", qtype: " << (rr.qtype).getName() << ", priority: " << rr.priority << ", ttl: " << rr.ttl << ", content: " << rr.content << endl );
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
        	while( m_pldap->getSearchEntry( m_msgid, m_result, m_getdn ) && prepare() );

        }
        catch( LDAPTimeout &lt )
        {
        	L << Logger::Warning << m_myname << " Search failed: " << lt.what() << endl;
        	throw( DBException( "LDAP server timeout" ) );
        }
        catch( LDAPException &le )
        {
        	L << Logger::Error << m_myname << " Search failed: " << le.what() << endl;
        	throw( PDNSException( "LDAP server unreachable" ) );   // try to reconnect to another server
        }
        catch( std::exception &e )
        {
        	L << Logger::Error << m_myname << " Caught STL exception for " << m_qname << ": " << e.what() << endl;
        	throw( DBException( "STL exception" ) );
        }

        return false;
}



 bool LdapBackend::getDomainInfo( const string& domain, DomainInfo& di )
{
        string filter;
        SOAData sd;
        const char* attronly[] = { "sOARecord", NULL };


        // search for SOARecord of domain
        filter = "(&(associatedDomain=" + toLower( m_pldap->escape( domain ) ) + ")(SOARecord=*))";
        m_msgid = m_pldap->search( getArg( "basedn" ), LDAP_SCOPE_SUBTREE, filter, attronly );
        m_pldap->getSearchEntry( m_msgid, m_result );

        if( m_result.count( "sOARecord" ) && !m_result["sOARecord"].empty() )
        {
        	sd.serial = 0;
        	fillSOAData( m_result["sOARecord"][0], sd );

        	di.id = 0;
        	di.serial = sd.serial;
        	di.zone = domain;
        	di.last_check = 0;
        	di.backend = this;
        	di.kind = DomainInfo::Master;

        	return true;
        }

        return false;
}





class LdapFactory : public BackendFactory
{

public:

        LdapFactory() : BackendFactory( "ldap" ) {}


        void declareArguments( const string &suffix="" )
        {
        	declare( suffix, "host", "One or more LDAP server with ports or LDAP URIs (separated by spaces)","ldap://127.0.0.1:389/" );
        	declare( suffix, "starttls", "Use TLS to encrypt connection (unused for LDAP URIs)", "no" );
        	declare( suffix, "basedn", "Search root in ldap tree (must be set)","" );
        	declare( suffix, "basedn-axfr-override", "Override base dn for AXFR subtree search", "no" );
        	declare( suffix, "binddn", "User dn for non anonymous binds","" );
        	declare( suffix, "secret", "User password for non anonymous binds", "" );
        	declare( suffix, "timeout", "Seconds before connecting to server fails", "5" );
        	declare( suffix, "method", "How to search entries (simple, strict or tree)", "simple" );
        	declare( suffix, "filter-axfr", "LDAP filter for limiting AXFR results", "(:target:)" );
        	declare( suffix, "filter-lookup", "LDAP filter for limiting IP or name lookups", "(:target:)" );
        	declare( suffix, "disable-ptrrecord", "Deprecated, use ldap-method=strict instead", "no" );
        }


        DNSBackend* make( const string &suffix="" )
        {
        	return new LdapBackend( suffix );
        }
};





class LdapLoader
{
        LdapFactory factory;

public:

        LdapLoader()
        {
        	BackendMakers().report( &factory );
		L << Logger::Info << "[ldapbackend] This is the ldap backend version " VERSION " reporting" << endl;
        }
};


static LdapLoader ldaploader;
