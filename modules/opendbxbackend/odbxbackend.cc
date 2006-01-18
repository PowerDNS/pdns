#include "odbxbackend.hh"



unsigned int odbx_host_index = 0;



OdbxBackend::OdbxBackend( const string& suffix )
{
	int err = -1;
	unsigned int  idx, i, h;
	vector<string> hosts;


	try
	{
		m_result = NULL;
		m_myname = "[OpendbxBackend]";
		m_default_ttl = arg().asNum( "default-ttl" );
		m_qlog = arg().mustDo( "query-logging" );

		setArgPrefix( "opendbx" + suffix );
		stringtok( hosts, getArg( "host" ), ", " );

		idx = odbx_host_index++ % hosts.size();

		for( i = 0; i < hosts.size(); i++ )
		{
			h = ( idx + i ) % hosts.size();
			if( !( err = odbx_init( &m_handle, getArg( "backend" ).c_str(), hosts[h].c_str(), getArg( "port" ).c_str() ) ) ) { break; }
		}

		if( err < 0 )
		{
			L.log( m_myname + " OdbxBackend: Unable to connect to server - " + string( odbx_error( m_handle, err ) ),  Logger::Error );
			throw( AhuException( "Fatal: odbx_init() failed" ) );
		}

		if( ( err = odbx_bind_simple( m_handle, getArg( "database" ).c_str(), getArg( "username" ).c_str(), getArg( "password" ).c_str() ) ) < 0 )
		{
			L.log( m_myname + " OdbxBackend: Unable to bind to database - " + string( odbx_error( m_handle, err ) ),  Logger::Error );
			throw( AhuException( "Fatal: odbx_bind_simple() failed" ) );
		}
	}
	catch( exception& e )
	{
		L.log( m_myname + " OdbxBackend: Caught STL exception - " + e.what(),  Logger::Error );
		throw( DBException( "Fatal: STL exception" ) );
	}

	L.log( m_myname + " Connection succeeded", Logger::Notice );
}



OdbxBackend::~OdbxBackend()
{
	odbx_unbind( m_handle );
	odbx_finish( m_handle );
}



bool OdbxBackend::getDomainInfo( const string& domain, DomainInfo& di )
{
	const char* tmp;
	string stmt;


	try
	{
		DLOG( L.log( m_myname + " getDomainInfo()", Logger::Debug ) );

		stmt = strbind( ":name", escape( toLower( domain ) ), getArg( "sql-zoneinfo" ) );
		execStmt( stmt.c_str(), stmt.size(), true );

		if( !getRecord() ) { return false; }

		do
		{
			di.id = 0;
			di.zone = "";
			di.master = "";
			di.last_check = 0;
			di.notified_serial = 0;
			di.kind = DomainInfo::Native;
			di.backend = this;
			di.serial = 0;

			if( ( tmp = odbx_field_value( m_result, 0 ) ) != NULL )
			{
				di.id = strtol( tmp, NULL, 10 );
			}

			if( ( tmp = odbx_field_value( m_result, 1 ) ) != NULL )
			{
				di.zone = string( tmp );
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

			if( ( tmp = odbx_field_value( m_result, 3 ) ) != NULL )
			{
				di.master = string( tmp );
			}

			if( ( tmp = odbx_field_value( m_result, 5 ) ) != NULL )
			{
				di.last_check = strtol( tmp, NULL, 10 );
			}

			if( ( tmp = odbx_field_value( m_result, 6 ) ) != NULL )
			{
				SOAData sd;

				sd.serial = 0;
					DNSPacket::fillSOAData( string( tmp ), sd );
				di.serial = sd.serial;
			}
		}
		while( getRecord() );
	}
	catch( exception& e )
	{
		L.log( m_myname + " getDomainInfo: Caught STL exception - " + e.what(),  Logger::Error );
		throw( DBException( "Error: STL exception" ) );
	}

	return true;
}



bool OdbxBackend::list( const string& target, int zoneid )
{
	string stmt;
	size_t len;



	try
	{
		DLOG( L.log( m_myname + " list()", Logger::Debug ) );

		m_qname = "";
		m_result = NULL;

		len = snprintf( m_buffer, sizeof( m_buffer ) - 1, "%d", zoneid );

		if( len < 0 || len > sizeof( m_buffer ) - 1 )
		{
			L.log( m_myname + " list: Unable to convert zone id to string",  Logger::Error );
			throw( DBException( "Error: Libc error" ) );
		}

		stmt = strbind( ":id", string( m_buffer, len ), getArg( "sql-list" ) );

		execStmt( stmt.c_str(), stmt.size(), true );
	}
	catch( exception& e )
	{
		L.log( m_myname + " list: Caught STL exception - " + e.what(),  Logger::Error );
		throw( DBException( "Error: STL exception" ) );
	}

	return true;
}



void OdbxBackend::lookup( const QType& qtype, const string& qname, DNSPacket* dnspkt, int zoneid )
{
	string stmt;


	try
	{
		DLOG( L.log( m_myname + " lookup()", Logger::Debug ) );

		m_result = NULL;
		m_qname = qname;
		
		if( zoneid < 0 )
		{
			if( qtype.getCode() == QType::ANY )
			{
				stmt = getArg( "sql-lookup" );
			} else {
				stmt = strbind( ":type", qtype.getName(), getArg( "sql-lookuptype" ) );
			}
		}
		else
		{
			if( qtype.getCode() == QType::ANY )
			{
	 			stmt = getArg( "sql-lookupid" );
			} else {
				stmt = strbind( ":type", qtype.getName(), getArg( "sql-lookuptypeid" ) );
			}
 			
			size_t len = snprintf( m_buffer, sizeof( m_buffer ) - 1, "%d", zoneid );

			if( len < 0 || len > sizeof( m_buffer ) - 1 )
			{
				L.log( m_myname + " lookup: Unable to convert zone id to string",  Logger::Error );
				throw( DBException( "Error: Libc error" ) );
			}

			stmt = strbind( ":id", string( m_buffer, len ), stmt );
		}

		stmt = strbind( ":name", escape( toLower( qname ) ), stmt );
		execStmt( stmt.c_str(), stmt.size(), true );
	}
	catch( exception& e )
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

		if( getRecord() )
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
				rr.qname = string( tmp );
			}

			if( ( tmp = odbx_field_value( m_result, 2 ) ) != NULL )
			{
				rr.qtype = QType( tmp );
			}

			if( ( tmp = odbx_field_value( m_result, 3 ) ) != NULL )
			{
				rr.ttl = strtoul( tmp, NULL, 10 );
			}

			if( ( tmp = odbx_field_value( m_result, 4 ) ) != NULL )
			{
				rr.priority = (u_int16_t) strtoul( tmp, NULL, 10 );
			}

			if( ( tmp = odbx_field_value( m_result, 5 ) ) != NULL )
			{
				rr.content = string( tmp );
			}

			return true;
		}
	}
	catch( exception& e )
	{
		L.log( m_myname + " get: Caught STL exception - " + e.what(),  Logger::Error );
		throw( DBException( "Error: STL exception" ) );
	}

	return false;
}


void OdbxBackend::setFresh( u_int32_t domain_id )
{
	size_t len;


	try
	{
		DLOG( L.log( m_myname + " setFresh()", Logger::Debug ) );

		len = snprintf( m_buffer, sizeof( m_buffer ) - 1, getArg( "sql-update-lastcheck" ).c_str(), time( 0 ), domain_id );

		if( len < 0 || len > sizeof( m_buffer ) - 1 )
		{
			L.log( m_myname + " setFresh: Unable to insert values into statement '" + getArg( "sql-update-lastcheck" ) + "'",  Logger::Error );
			throw( DBException( "Error: Libc error" ) );
		}

		execStmt( m_buffer, len, false );
	}
	catch ( exception& e )
	{
		L.log( m_myname + " setFresh: Caught STL exception - " + e.what(),  Logger::Error );
		throw( DBException( "Error: STL exception" ) );
	}
}



void OdbxBackend::setNotified( u_int32_t domain_id, u_int32_t serial )
{
	size_t len;


	try
	{
		DLOG( L.log( m_myname + " setNotified()", Logger::Debug ) );

		len = snprintf( m_buffer, sizeof( m_buffer ) - 1, getArg( "sql-update-serial" ).c_str(), serial, domain_id );

		if( len < 0 || len > sizeof( m_buffer ) - 1 )
		{
			L.log( m_myname + " setNotified: Unable to insert values into statement '" + getArg( "sql-update-serial" ) + "'",  Logger::Error );
			throw( DBException( "Error: Libc error" ) );
		}

		execStmt( m_buffer, len, false );
	}
	catch ( exception& e )
	{
		L.log( m_myname + " setNotified: Caught STL exception - " + e.what(),  Logger::Error );
		throw( DBException( "Error: STL exception" ) );
	}
}



bool OdbxBackend::isMaster( const string& domain, const string& ip )
{
	string stmt;


	try
	{
		DLOG( L.log( m_myname + " isMaster()", Logger::Debug ) );

		stmt = strbind( ":name", escape( toLower( domain ) ), getArg( "sql-master" ) );
		execStmt( stmt.c_str(), stmt.size(), true );

		if( !getRecord() ) { return false; }

		do
		{
			if( odbx_field_value( m_result, 0 ) != NULL )
			{
				if( !strcmp( odbx_field_value( m_result, 0 ), ip.c_str() ) )
				{
					return true;
				}
			}
		}
		while( getRecord() );
	}
	catch ( exception& e )
	{
		L.log( m_myname + " isMaster: Caught STL exception - " + e.what(),  Logger::Error );
		throw( DBException( "Error: STL exception" ) );
	}

	return false;
}



void OdbxBackend::getUnfreshSlaveInfos( vector<DomainInfo>* unfresh )
{
	try
	{
		DLOG( L.log( m_myname + " getUnfreshSlaveInfos()", Logger::Debug ) );

		if( unfresh != NULL )
		{
			getDomainList( getArg( "sql-infoslaves" ), unfresh, &checkSlave );
		}
	}
	catch ( exception& e )
	{
		L.log( m_myname + " getUnfreshSlaveInfo: Caught STL exception - " + e.what(),  Logger::Error );
		throw( DBException( "Error: STL exception" ) );
	}
}



void OdbxBackend::getUpdatedMasters( vector<DomainInfo>* updated )
{
	try
	{
		DLOG( L.log( m_myname + " getUpdatedMasters()", Logger::Debug ) );

		if( updated != NULL )
		{
			getDomainList( getArg( "sql-infomasters" ), updated, &checkMaster );
		}
	}
	catch ( exception& e )
	{
		L.log( m_myname + " getUpdatedMasters: Caught STL exception - " + e.what(),  Logger::Error );
		throw( DBException( "Error: STL exception" ) );
	}
}



bool OdbxBackend::superMasterBackend( const string& ip, const string& domain, const vector<DNSResourceRecord>& set, string* account, DNSBackend** ddb )
{
	string stmt;
	vector<DNSResourceRecord>::const_iterator i;


	try
	{
		DLOG( L.log( m_myname + " superMasterBackend()", Logger::Debug ) );

		if( account != NULL && ddb != NULL )
		{
			for( i = set.begin(); i != set.end(); i++ )
			{
				stmt = strbind( ":ip", escape( ip ), getArg( "sql-supermaster" ) );
				stmt = strbind( ":ns", escape( i->content ), stmt );

				execStmt( stmt.c_str(), stmt.size(), true );

				if( !getRecord() ) { return false; }

				do
				{
					if( odbx_field_value( m_result, 0 ) != NULL )
					{
						*account = string( odbx_field_value( m_result, 0 ), odbx_field_length( m_result, 0 ) );
					}
				}
				while( getRecord() );

				*ddb=this;
				return true;
			}
		}
	}
	catch ( exception& e )
	{
		L.log( m_myname + " superMasterBackend: Caught STL exception - " + e.what(),  Logger::Error );
		throw( DBException( "Error: STL exception" ) );
	}

	return false;
}



bool OdbxBackend::createSlaveDomain( const string& ip, const string& domain, const string& account )
{
	size_t len;


	try
	{
		DLOG( L.log( m_myname + " createSlaveDomain()", Logger::Debug ) );

		len = snprintf( m_buffer, sizeof( m_buffer ) - 1, getArg( "sql-insert-slave" ).c_str(), escape( toLower( domain ) ).c_str(),
			escape( ip ).c_str(), escape( account ).c_str() );

		if( len < 0 || len > sizeof( m_buffer ) - 1 )
		{
			L.log( m_myname + " createSlaveDomain: Unable to insert values in statement '" + getArg( "sql-insert-slave" ) + "'",  Logger::Error );
			throw( DBException( "Error: Libc error" ) );
		}

		execStmt( m_buffer, len, false );
	}
	catch ( exception& e )
	{
		L.log( m_myname + " createSlaveDomain: Caught STL exception - " + e.what(),  Logger::Error );
		throw( DBException( "Error: STL exception" ) );
	}

	return true;
}



bool OdbxBackend::feedRecord( const DNSResourceRecord& rr )
{
	size_t len;


	try
	{
		DLOG( L.log( m_myname + " feedRecord()", Logger::Debug ) );

		len = snprintf( m_buffer, sizeof( m_buffer ) - 1, getArg( "sql-insert-record" ).c_str(), rr.domain_id,
			escape( toLower( rr.qname ) ).c_str(), rr.qtype.getName().c_str(), rr.ttl, rr.priority, escape( rr.content ).c_str() );

		if( len < 0 || len > sizeof( m_buffer ) - 1 )
		{
			L.log( m_myname + " feedRecord: Unable to insert values in statement '" + getArg( "sql-insert-record" ) + "'",  Logger::Error );
			throw( DBException( "Error: Libc error" ) );
		}

		execStmt( m_buffer, len, false );
	}
	catch ( exception& e )
	{
		L.log( m_myname + " feedRecord: Caught STL exception - " + e.what(),  Logger::Error );
		throw( DBException( "Error: STL exception" ) );
	}

	return true;
}



bool OdbxBackend::startTransaction( const string& domain, int zoneid )
{
	size_t len;
	string stmt;


	try
	{
		DLOG( L.log( m_myname + " startTransaction()", Logger::Debug ) );

		stmt = getArg( "sql-transactbegin" );
		execStmt( stmt.c_str(), stmt.size(), false );

		len = snprintf( m_buffer, sizeof( m_buffer ) - 1, "%d", zoneid );

		if( len < 0 || len > sizeof( m_buffer ) - 1 )
		{
			L.log( m_myname + " lookup: Unable to convert zone id to string",  Logger::Error );
			throw( DBException( "Error: Libc error" ) );
		}

		stmt = strbind( ":id", string( m_buffer, len ), getArg( "sql-zonedelete" ) );

		execStmt( stmt.c_str(), stmt.size(), false );
	}
	catch ( exception& e )
	{
		L.log( m_myname + " startTransaction: Caught STL exception - " + e.what(),  Logger::Error );
		throw( DBException( "Error: STL exception" ) );
	}

	return true;
}



bool OdbxBackend::commitTransaction()
{
	try
	{
		DLOG( L.log( m_myname + " commitTransaction()", Logger::Debug ) );

		execStmt( getArg( "sql-transactend" ).c_str(), getArg( "sql-transactend" ).size(), false );
	}
	catch ( exception& e )
	{
		L.log( m_myname + " commitTransaction: Caught STL exception - " + e.what(),  Logger::Error );
		throw( DBException( "Error: STL exception" ) );
	}

	return true;
}



bool OdbxBackend::abortTransaction()
{
	try
	{
		DLOG( L.log( m_myname + " abortTransaction()", Logger::Debug ) );

		execStmt( getArg( "sql-transactabort" ).c_str(), getArg( "sql-transabort" ).size(), false );
	}
	catch ( exception& e )
	{
		L.log( m_myname + " abortTransaction: Caught STL exception - " + e.what(),  Logger::Error );
		throw( DBException( "Error: STL exception" ) );
	}

	return true;
}
