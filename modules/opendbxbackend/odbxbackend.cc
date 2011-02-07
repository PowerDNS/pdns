#include "odbxbackend.hh"



inline string& strbind( const string& search, const string& replace, string& subject )
{
        size_t pos = 0;

        while( ( pos = subject.find( search, pos ) ) != string::npos )
        {
        	subject.replace( pos, search.size(), replace );
        	pos += replace.size();
        }

        return subject;
}



inline string& toLowerByRef( string& str )
{
        for( unsigned int i = 0; i < str.length(); i++ )
        {
        	str[i] = dns_tolower( str[i] );
        }

        return str;
}



OdbxBackend::OdbxBackend( const string& suffix )
{
        vector<string> hosts;


        try
        {
        	m_result = NULL;
        	m_handle[READ] = NULL;
        	m_handle[WRITE] = NULL;
        	m_myname = "[OpendbxBackend]";
        	m_default_ttl = arg().asNum( "default-ttl" );
        	m_qlog = arg().mustDo( "query-logging" );

        	setArgPrefix( "opendbx" + suffix );

        	if( getArg( "host" ).size() > 0 )
        	{
        		L.log( m_myname + " WARNING: Using depricated opendbx-host parameter", Logger::Warning );
        		stringtok( m_hosts[READ], getArg( "host" ), ", " );
        		m_hosts[WRITE] = m_hosts[READ];
        	}
        	else
        	{
        		stringtok( m_hosts[READ], getArg( "host-read" ), ", " );
        		stringtok( m_hosts[WRITE], getArg( "host-write" ), ", " );
        	}

        	if( !connectTo( m_hosts[READ], READ ) ) { throw( AhuException( "Fatal: Connecting to server for reading failed" ) ); }
        	if( !connectTo( m_hosts[WRITE], WRITE ) ) { throw( AhuException( "Fatal: Connecting to server for writing failed" ) ); }
        }
        catch( std::exception& e )
        {
        	L.log( m_myname + " OdbxBackend(): Caught STL exception - " + e.what(),  Logger::Error );
        	throw( AhuException( "Fatal: STL exception" ) );
        }
}



OdbxBackend::~OdbxBackend()
{
        odbx_unbind( m_handle[WRITE] );
        odbx_unbind( m_handle[READ] );

        odbx_finish( m_handle[WRITE] );
        odbx_finish( m_handle[READ] );
}



bool OdbxBackend::getDomainInfo( const string& domain, DomainInfo& di )
{
        const char* tmp;


        try
        {
        	DLOG( L.log( m_myname + " getDomainInfo()", Logger::Debug ) );

        	string stmt = getArg( "sql-zoneinfo" );
        	string& stmtref = strbind( ":name", escape( toLower( domain ), READ ), stmt );

        	if( !execStmt( stmtref.c_str(), stmtref.size(), READ ) ) { return false; }
        	if( !getRecord( READ ) ) { return false; }

        	do
        	{
        		di.id = 0;
        		di.zone = "";
        		di.masters.clear();
        		di.last_check = 0;
        		di.notified_serial = 0;
        		di.kind = DomainInfo::Native;
        		di.backend = this;
        		di.serial = 0;

        		if( ( tmp = odbx_field_value( m_result, 6 ) ) != NULL )
        		{
        			SOAData sd;

        			sd.serial = 0;
        			fillSOAData( string( tmp, odbx_field_length( m_result, 6 ) ), sd );

        			if( sd.serial == 0 && ( tmp = odbx_field_value( m_result, 5 ) ) != NULL )
        			{
        				sd.serial = strtol( tmp, NULL, 10 );
        			}

        			di.serial = sd.serial;
        		}

        		if( ( tmp = odbx_field_value( m_result, 4 ) ) != NULL )
        		{
        			di.last_check = strtol( tmp, NULL, 10 );
        		}

        		if( ( tmp = odbx_field_value( m_result, 3 ) ) != NULL )
        		{
        			stringtok(di.masters, string( tmp, odbx_field_length( m_result, 3 ) ), ", \t");
        		}

        		if( ( tmp = odbx_field_value( m_result, 2 ) ) != NULL )
        		{
        			if( !strncmp( tmp, "SLAVE", 5 ) )
        			{
        				di.kind = DomainInfo::Slave;
        			}
        			else if( !strncmp( tmp, "MASTER", 6 ) )
        			{
        				di.kind = DomainInfo::Master;
        			}
        		}

        		if( ( tmp = odbx_field_value( m_result, 1 ) ) != NULL )
        		{
        			di.zone = string( tmp, odbx_field_length( m_result, 1 ) );
        		}

        		if( ( tmp = odbx_field_value( m_result, 0 ) ) != NULL )
        		{
        			di.id = strtol( tmp, NULL, 10 );
        		}
        	}
        	while( getRecord( READ ) );
        }
        catch( std::exception& e )
        {
        	L.log( m_myname + " getDomainInfo: Caught STL std::exception - " + e.what(),  Logger::Error );
        	return false;
        }

        return true;
}



bool OdbxBackend::getSOA( const string& domain, SOAData& sd, DNSPacket* p )
{
        const char* tmp;


        try
        {
        	DLOG( L.log( m_myname + " getSOA()", Logger::Debug ) );

        	string stmt = getArg( "sql-lookupsoa" );
        	string& stmtref = strbind( ":name", escape( toLower( domain ), READ ), stmt );

        	if( !execStmt( stmtref.c_str(), stmtref.size(), READ ) ) { return false; }
        	if( !getRecord( READ ) ) { return false; }

        	do
        	{
        		sd.serial = 0;
        		sd.ttl = m_default_ttl;

        		if( ( tmp = odbx_field_value( m_result, 3 ) ) != NULL )
        		{
        			fillSOAData( string( tmp, odbx_field_length( m_result, 3 ) ), sd );
        		}

        		if( ( tmp = odbx_field_value( m_result, 2 ) ) != NULL )
        		{
        			sd.ttl = strtoul( tmp, NULL, 10 );
        		} 

        		if( sd.serial == 0 && ( tmp = odbx_field_value( m_result, 1 ) ) != NULL )
        		{
        			sd.serial = strtol( tmp, NULL, 10 );
        		}

        		if( ( tmp = odbx_field_value( m_result, 0 ) ) != NULL )
        		{
        			sd.domain_id = strtol( tmp, NULL, 10 );
        		}

        		if( sd.nameserver.empty() )
        		{
        			sd.nameserver = arg()["default-soa-name"];
        		}

        		if( sd.hostmaster.empty() )
        		{
        			sd.hostmaster = "hostmaster." + domain;
        		}

        		sd.db = this;
        	}
        	while( getRecord( READ ) );
        }
        catch( std::exception& e )
        {
        	L.log( m_myname + " getSOA: Caught STL exception - " + e.what(),  Logger::Error );
        	return false;
        }

        return true;
}



bool OdbxBackend::list( const string& target, int zoneid )
{
        try
        {
        	DLOG( L.log( m_myname + " list()", Logger::Debug ) );

        	m_qname = "";
        	m_result = NULL;

        	size_t len = snprintf( m_buffer, sizeof( m_buffer ) - 1, "%d", zoneid );

        	if( len < 0 )
        	{
        		L.log( m_myname + " list: Unable to convert zone id to string - format error",  Logger::Error );
        		return false;
        	}

        	if( len > sizeof( m_buffer ) - 1 )
        	{
        		L.log( m_myname + " list: Unable to convert zone id to string - insufficient buffer space",  Logger::Error );
        		return false;
        	}

        	string stmt = getArg( "sql-list" );
        	string& stmtref = strbind( ":id", string( m_buffer, len ), stmt );

        	if( !execStmt( stmtref.c_str(), stmtref.size(), READ ) ) { return false; }
        }
        catch( std::exception& e )
        {
        	L.log( m_myname + " list: Caught STL exception - " + e.what(),  Logger::Error );
        	return false;
        }

        return true;
}



void OdbxBackend::lookup( const QType& qtype, const string& qname, DNSPacket* dnspkt, int zoneid )
{
        try
        {
        	DLOG( L.log( m_myname + " lookup()", Logger::Debug ) );

        	string stmt;
        	string& stmtref = stmt;

        	m_result = NULL;
        	m_qname = qname;

        	if( zoneid < 0 )
        	{
        		if( qtype.getCode() == QType::ANY )
        		{
        			stmt = getArg( "sql-lookup" );
        		} else {
        			stmt = getArg( "sql-lookuptype" );
        			stmtref = strbind( ":type", qtype.getName(), stmt );
        		}
        	}
        	else
        	{
        		if( qtype.getCode() == QType::ANY )
        		{
         			stmt = getArg( "sql-lookupid" );
        		} else {
        			stmt = getArg( "sql-lookuptypeid" );
        			stmtref = strbind( ":type", qtype.getName(), stmt );
        		}

        		size_t len = snprintf( m_buffer, sizeof( m_buffer ) - 1, "%d", zoneid );

        		if( len < 0 )
        		{
        			L.log( m_myname + " lookup: Unable to convert zone id to string - format error",  Logger::Error );
        			throw( DBException( "Error: Libc error" ) );
        		}

        		if( len > sizeof( m_buffer ) - 1 )
        		{
        			L.log( m_myname + " lookup: Unable to convert zone id to string - insufficient buffer space",  Logger::Error );
        			throw( DBException( "Error: Libc error" ) );
        	}

        		stmtref = strbind( ":id", string( m_buffer, len ), stmtref );
        	}

        	string tmp = qname;
        	stmtref = strbind( ":name", escape( toLowerByRef( tmp ), READ ), stmtref );

        	if( !execStmt( stmtref.c_str(), stmtref.size(), READ ) )
        	{
        		throw( DBException( "Error: DB statement failed" ) );
        	}
        }
        catch( std::exception& e )
        {
        	L.log( m_myname + " lookup: Caught STL exception - " + e.what(),  Logger::Error );
        	throw( DBException( "Error: STL exception" ) );
        }
}



bool OdbxBackend::get( DNSResourceRecord& rr )
{
        const char* tmp;


        try
        {
        	DLOG( L.log( m_myname + " get()", Logger::Debug ) );

        	if( getRecord( READ ) )
        	{
        		rr.content = "";
        		rr.priority = 0;
        		rr.domain_id = 0;
        		rr.last_modified = 0;
        		rr.ttl = m_default_ttl;
        		rr.qname = m_qname;

        		if( ( tmp = odbx_field_value( m_result, 0 ) ) != NULL )
        		{
        			rr.domain_id = strtol( tmp, NULL, 10 );
        		}

        		if( m_qname.empty() && ( tmp = odbx_field_value( m_result, 1 ) ) != NULL )
        		{
        			rr.qname = string( tmp, odbx_field_length( m_result, 1 ) );
        		}

        		if( ( tmp = odbx_field_value( m_result, 2 ) ) != NULL )
        		{
        			rr.qtype = tmp;
        		}

        		if( ( tmp = odbx_field_value( m_result, 3 ) ) != NULL )
        		{
        			rr.ttl = strtoul( tmp, NULL, 10 );
        		}

        		if( ( tmp = odbx_field_value( m_result, 4 ) ) != NULL )
        		{
        			rr.priority = (uint16_t) strtoul( tmp, NULL, 10 );
        		}

        		if( ( tmp = odbx_field_value( m_result, 5 ) ) != NULL )
        		{
        			rr.content = string( tmp, odbx_field_length( m_result, 5 ) );
        		}

        		return true;
        	}
        }
        catch( std::exception& e )
        {
        	L.log( m_myname + " get: Caught STL exception - " + e.what(),  Logger::Error );
        	return false;
        }

        return false;
}


void OdbxBackend::setFresh( uint32_t domain_id )
{
        size_t len;


        try
        {
        	DLOG( L.log( m_myname + " setFresh()", Logger::Debug ) );

        	if( !m_handle[WRITE] && !connectTo( m_hosts[WRITE], WRITE ) )
        	{
        		L.log( m_myname + " setFresh: Master server is unreachable",  Logger::Error );
        		throw( DBException( "Error: Server unreachable" ) );
        	}

        	len = snprintf( m_buffer, sizeof( m_buffer ) - 1, getArg( "sql-update-lastcheck" ).c_str(), time( 0 ), domain_id );

        	if( len < 0 )
        	{
        		L.log( m_myname + " setFresh: Unable to insert values into statement '" + getArg( "sql-update-lastcheck" ) + "' - format error",  Logger::Error );
        		throw( DBException( "Error: Libc error" ) );
        	}

        	if( len > sizeof( m_buffer ) - 1 )
        	{
        		L.log( m_myname + " setFresh: Unable to insert values into statement '" + getArg( "sql-update-lastcheck" ) + "' - insufficient buffer space",  Logger::Error );
        		throw( DBException( "Error: Libc error" ) );
        	}

        	if( !execStmt( m_buffer, len, WRITE ) )
        	{
        		throw( DBException( "Error: DB statement failed" ) );
        	}
        }
        catch ( std::exception& e )
        {
        	L.log( m_myname + " setFresh: Caught STL exception - " + e.what(),  Logger::Error );
        	throw( DBException( "Error: STL exception" ) );
        }
}



void OdbxBackend::setNotified( uint32_t domain_id, uint32_t serial )
{
        try
        {
        	DLOG( L.log( m_myname + " setNotified()", Logger::Debug ) );

        	if( !m_handle[WRITE] && !connectTo( m_hosts[WRITE], WRITE ) )
        	{
        		L.log( m_myname + " setFresh: Master server is unreachable",  Logger::Error );
        		throw( DBException( "Error: Server unreachable" ) );
        	}

        	size_t len = snprintf( m_buffer, sizeof( m_buffer ) - 1, getArg( "sql-update-serial" ).c_str(), serial, domain_id );

        	if( len < 0 )
        	{
        		L.log( m_myname + " setNotified: Unable to insert values into statement '" + getArg( "sql-update-serial" ) + "' - format error",  Logger::Error );
        		throw( DBException( "Error: Libc error" ) );
        	}

        	if( len > sizeof( m_buffer ) - 1 )
        	{
        		L.log( m_myname + " setNotified: Unable to insert values into statement '" + getArg( "sql-update-serial" ) + "' - insufficient buffer space",  Logger::Error );
        		throw( DBException( "Error: Libc error" ) );
        	}

        	if( !execStmt( m_buffer, len, WRITE ) )
        	{
        		throw( DBException( "Error: DB statement failed" ) );
        	}
        }
        catch ( std::exception& e )
        {
        	L.log( m_myname + " setNotified: Caught STL exception - " + e.what(),  Logger::Error );
        	throw( DBException( "Error: STL exception" ) );
        }
}



bool OdbxBackend::isMaster( const string& domain, const string& ip )
{
        try
        {
        	DLOG( L.log( m_myname + " isMaster()", Logger::Debug ) );

        	string stmt = getArg( "sql-master" );
        	string& stmtref = strbind( ":name", escape( toLower( domain ), READ ), stmt );

        	if( !execStmt( stmtref.c_str(), stmtref.size(), READ ) ) { return false; }
        	if( !getRecord( READ ) ) { return false; }

        	do
        	{
        		if( odbx_field_value( m_result, 0 ) != NULL )
        		{
        			if( !strcmp( odbx_field_value( m_result, 0 ), ip.c_str() ) )
        			{
        				while( getRecord( READ ) );
        				return true;
        			}
        		}
        	}
        	while( getRecord( READ ) );
        }
        catch ( std::exception& e )
        {
        	L.log( m_myname + " isMaster: Caught STL exception - " + e.what(),  Logger::Error );
        	return false;
        }

        return false;
}



void OdbxBackend::getUnfreshSlaveInfos( vector<DomainInfo>* unfresh )
{
        try
        {
        	DLOG( L.log( m_myname + " getUnfreshSlaveInfos()", Logger::Debug ) );

        	if( unfresh == NULL )
        	{
        		L.log( m_myname + " getUnfreshSlaveInfos: invalid parameter - NULL pointer",  Logger::Error );
        		return;
        	}

        	getDomainList( getArg( "sql-infoslaves" ), unfresh, &checkSlave );
        }
        catch ( std::exception& e )
        {
        	L.log( m_myname + " getUnfreshSlaveInfo: Caught STL exception - " + e.what(),  Logger::Error );
        }
}



void OdbxBackend::getUpdatedMasters( vector<DomainInfo>* updated )
{
        try
        {
        	DLOG( L.log( m_myname + " getUpdatedMasters()", Logger::Debug ) );

        	if( updated == NULL )
        	{
        		L.log( m_myname + " getUpdatedMasters: invalid parameter - NULL pointer",  Logger::Error );
        		return;
        	}

        	getDomainList( getArg( "sql-infomasters" ), updated, &checkMaster );
        }
        catch ( std::exception& e )
        {
        	L.log( m_myname + " getUpdatedMasters: Caught STL exception - " + e.what(),  Logger::Error );
        }
}



bool OdbxBackend::superMasterBackend( const string& ip, const string& domain, const vector<DNSResourceRecord>& set, string* account, DNSBackend** ddb )
{
        try
        {
        	DLOG( L.log( m_myname + " superMasterBackend()", Logger::Debug ) );

        	if( account != NULL && ddb != NULL )
        	{
        		vector<DNSResourceRecord>::const_iterator i;

        		for( i = set.begin(); i != set.end(); i++ )
        		{
        			string stmt = getArg( "sql-supermaster" );
        			string& stmtref = strbind( ":ip", escape( ip, READ ), stmt );
        			stmtref = strbind( ":ns", escape( i->content, READ ), stmtref );

        			if( !execStmt( stmtref.c_str(), stmtref.size(), READ ) ) { return false; }

        			if( getRecord( READ ) )
        			{
        				if( odbx_field_value( m_result, 0 ) != NULL )
        				{
        					*account = string( odbx_field_value( m_result, 0 ), odbx_field_length( m_result, 0 ) );
        				}

        				while( getRecord( READ ) );

        			*ddb=this;
        			return true;
        		}
        	}
        }
        }
        catch ( std::exception& e )
        {
        	L.log( m_myname + " superMasterBackend: Caught STL exception - " + e.what(),  Logger::Error );
        	return false;
        }

        return false;
}



bool OdbxBackend::createSlaveDomain( const string& ip, const string& domain, const string& account )
{
        try
        {
        	DLOG( L.log( m_myname + " createSlaveDomain()", Logger::Debug ) );

        	if( !m_handle[WRITE] && !connectTo( m_hosts[WRITE], WRITE ) )
        	{
        		L.log( m_myname + " createSlaveDomain: Master server is unreachable",  Logger::Error );
        		return false;
        	}

        	string tmp = domain;
        	size_t len = snprintf( m_buffer, sizeof( m_buffer ) - 1, getArg( "sql-insert-slave" ).c_str(), escape( toLowerByRef( tmp ), WRITE ).c_str(),
        		escape( ip, WRITE ).c_str(), escape( account, WRITE ).c_str() );

        	if( len < 0 )
        	{
        		L.log( m_myname + " createSlaveDomain: Unable to insert values in statement '" + getArg( "sql-insert-slave" ) + "' - format error",  Logger::Error );
        		return false;
        	}

        	if( len > sizeof( m_buffer ) - 1 )
        	{
        		L.log( m_myname + " createSlaveDomain: Unable to insert values in statement '" + getArg( "sql-insert-slave" ) + "' - insufficient buffer space",  Logger::Error );
        		return false;
        	}

        	if( !execStmt( m_buffer, len, WRITE ) ) { return false; }
        }
        catch ( std::exception& e )
        {
        	L.log( m_myname + " createSlaveDomain: Caught STL exception - " + e.what(),  Logger::Error );
        	return false;
        }

        return true;
}



bool OdbxBackend::feedRecord( const DNSResourceRecord& rr )
{
        try
        {
        	DLOG( L.log( m_myname + " feedRecord()", Logger::Debug ) );

        	if( !m_handle[WRITE] && !connectTo( m_hosts[WRITE], WRITE ) )
        	{
        		L.log( m_myname + " feedRecord: Master server is unreachable",  Logger::Error );
        		return false;
        	}

        	string tmp = rr.qname;
        	size_t len = snprintf( m_buffer, sizeof( m_buffer ) - 1, getArg( "sql-insert-record" ).c_str(), rr.domain_id,
        		escape( toLowerByRef( tmp ), WRITE ).c_str(), rr.qtype.getName().c_str(), rr.ttl, rr.priority,
        		escape( rr.content, WRITE ).c_str() );

        	if( len < 0 )
        	{
        		L.log( m_myname + " feedRecord: Unable to insert values in statement '" + getArg( "sql-insert-record" ) + "' - format error",  Logger::Error );
        		return false;
        	}

        	if( len > sizeof( m_buffer ) - 1 )
        	{
        		L.log( m_myname + " feedRecord: Unable to insert values in statement '" + getArg( "sql-insert-record" ) + "' - insufficient buffer space",  Logger::Error );
        		return false;
        	}

        	if( !execStmt( m_buffer, len, WRITE ) ) { return false; }
        }
        catch ( std::exception& e )
        {
        	L.log( m_myname + " feedRecord: Caught STL exception - " + e.what(),  Logger::Error );
        	return false;
        }

        return true;
}



bool OdbxBackend::startTransaction( const string& domain, int zoneid )
{
        try
        {
        	DLOG( L.log( m_myname + " startTransaction()", Logger::Debug ) );

        	if( !m_handle[WRITE] && !connectTo( m_hosts[WRITE], WRITE ) )
        	{
        		L.log( m_myname + " startTransaction: Master server is unreachable",  Logger::Error );
        		return false;
        	}

		string stmtref =  getArg( "sql-transactbegin" );
		if( !execStmt( stmtref.c_str(), stmtref.size(), WRITE ) ) { return false; }
        	size_t len = snprintf( m_buffer, sizeof( m_buffer ) - 1, "%d", zoneid );

        	if( len < 0 )
        	{
        		L.log( m_myname + " startTransaction: Unable to convert zone id to string - format error",  Logger::Error );
        		return false;
        	}

        	if( len > sizeof( m_buffer ) - 1 )
        	{
        		L.log( m_myname + " startTransaction: Unable to convert zone id to string - insufficient buffer space",  Logger::Error );
        		return false;
        	}

                if(zoneid >= 0) {
        	        string stmt = getArg( "sql-zonedelete" );
        	        stmtref = strbind( ":id", string( m_buffer, len ), stmt );
        	        if( !execStmt( stmtref.c_str(), stmtref.size(), WRITE ) ) { return false; }
                }
        }
        catch ( std::exception& e )
        {
        	L.log( m_myname + " startTransaction: Caught STL exception - " + e.what(),  Logger::Error );
        	return false;
        }

        return true;
}



bool OdbxBackend::commitTransaction()
{
        try
        {
        	DLOG( L.log( m_myname + " commitTransaction()", Logger::Debug ) );

        	if( !m_handle[WRITE] && !connectTo( m_hosts[WRITE], WRITE ) )
        	{
        		L.log( m_myname + " commitTransaction: Master server is unreachable",  Logger::Error );
        		return false;
        	}

        	const string& stmt = getArg( "sql-transactend" );
        	if( !execStmt( stmt.c_str(), stmt.size(), WRITE ) ) { return false; }
        }
        catch ( std::exception& e )
        {
        	L.log( m_myname + " commitTransaction: Caught STL exception - " + e.what(),  Logger::Error );
        	return false;
        }

        return true;
}



bool OdbxBackend::abortTransaction()
{
        try
        {
        	DLOG( L.log( m_myname + " abortTransaction()", Logger::Debug ) );

        	if( !m_handle[WRITE] && !connectTo( m_hosts[WRITE], WRITE ) )
        	{
        		L.log( m_myname + " abortTransaction: Master server is unreachable",  Logger::Error );
        		return false;
        	}

        	const string& stmt = getArg( "sql-transactabort" );
        	if( !execStmt( stmt.c_str(), stmt.size(), WRITE ) ) { return false; }
        }
        catch ( std::exception& e )
        {
        	L.log( m_myname + " abortTransaction: Caught STL exception - " + e.what(),  Logger::Error );
        	return false;
        }

        return true;
}
