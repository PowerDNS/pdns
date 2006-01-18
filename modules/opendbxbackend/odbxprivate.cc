#include "odbxbackend.hh"



void OdbxBackend::execStmt( const char* stmt, unsigned long length, bool select )
{
	int err;


	DLOG( L.log( m_myname + " execStmt()", Logger::Debug ) );

	if( m_qlog ) { L.log( m_myname + " Query: " + stmt, Logger::Info ); }

	if( ( err = odbx_query( m_handle, stmt, length ) ) < 0 )
	{
		L.log( m_myname + " execStmt: Unable to execute query - " + string( odbx_error( m_handle, err ) ),  Logger::Error );
		throw( AhuException( "Error: odbx_query() failed" ) );
	}

	if( !select ) { while( getRecord() ); }
}



bool OdbxBackend::getRecord()
{
	int err = 3;


	DLOG( L.log( m_myname + " getRecord()", Logger::Debug ) );

	do
	{
		if( m_result != NULL )
		{
			if( err == 3 )
			{
				if( ( err = odbx_row_fetch( m_result ) ) < 0 )
				{
					L.log( m_myname + " getRecord: Unable to get next row - " + string( odbx_error( m_handle, err ) ),  Logger::Error );
					throw( AhuException( "Error: odbx_row_fetch() failed" ) );
				}

				if( err > 0 )
				{
#ifdef VERBOSELOG
					unsigned int i;
					string fields;

					for( i = 0; i < odbx_column_count( m_result ); i++ )
					{
						fields += string( odbx_column_name( m_result, i ) );

						if( odbx_field_value( m_result, i ) != NULL )
						{
							fields += "=" + string( odbx_field_value( m_result, i ) ) + ", ";
						}
						else
						{
							fields += "=NULL, ";
						}
					}

					L.log( m_myname + " Values: " + fields,  Logger::Error );
#endif
					return true;
				}

			}

			odbx_result_free( m_result );
			m_result = NULL;
		}
	}
	while( ( err =  odbx_result( m_handle, &m_result, NULL, 0 ) ) > 0 );

	if( err < 0 )
	{
		L.log( m_myname + " getRecord: Unable to get next result - " + string( odbx_error( m_handle, err ) ),  Logger::Error );
		throw( AhuException( "Error: odbx_result() failed" ) );
	}

	m_result = NULL;
	return false;
}



string OdbxBackend::escape( const string& str )
{
	int err;
	unsigned long len = sizeof( m_escbuf );


	DLOG( L.log( m_myname + " escape()", Logger::Debug ) );

	if( ( err = odbx_escape( m_handle, str.c_str(), str.size(), m_escbuf, &len ) ) < 0 )
	{
		L.log( m_myname + " escape: Unable to escape string - " + string( odbx_error( m_handle, err ) ),  Logger::Error );
		throw( AhuException( "Error: odbx_escape() failed" ) );
	}

	return string( m_escbuf, len );
}



void OdbxBackend::getDomainList( const string& stmt, vector<DomainInfo>* list, bool (*check_fcn)(u_int32_t,u_int32_t,SOAData*,DomainInfo*) )
{
	const char* tmp;
	u_int32_t nlast, nserial;
	DomainInfo di;
	SOAData sd;


	DLOG( L.log( m_myname + " getDomainList()", Logger::Debug ) );

	execStmt( stmt.c_str(), stmt.size(), true );

	if( !getRecord() ) { return; }

	do
	{
		nlast = 0;
		nserial = 0;
		sd.serial = 0;
		sd.refresh = 0;

		if( ( tmp = odbx_field_value( m_result, 6 ) ) != NULL )
		{
			DNSPacket::fillSOAData( string( tmp ), sd );
		}

		if( !sd.serial && ( tmp = odbx_field_value( m_result, 5 ) ) != NULL )
		{
			sd.serial = strtol( tmp, NULL, 10 );
		}

		if( ( tmp = odbx_field_value( m_result, 4 ) ) != NULL )
		{
			nlast = strtol( tmp, NULL, 10 );
		}

		if( ( tmp = odbx_field_value( m_result, 3 ) ) != NULL )
		{
			nserial = strtol( tmp, NULL, 10 );
		}

		if( (*check_fcn)( nlast, nserial, &sd, &di ) )
		{
			if( ( tmp = odbx_field_value( m_result, 2 ) ) != NULL )
			{
				di.master = string( tmp, odbx_field_length( m_result, 2 ) );
			}

			if( ( tmp = odbx_field_value( m_result, 1 ) ) != NULL )
			{
				di.zone = string( tmp, odbx_field_length( m_result, 1 ) );
			}

			if( ( tmp = odbx_field_value( m_result, 0 ) ) != NULL )
			{
				di.id = strtol( tmp, NULL, 10 );
			}

			di.last_check = nlast;
			di.notified_serial = nserial;
			di.serial = sd.serial;
			di.backend = this;

			list->push_back( di );
		}
	}
	while( getRecord() );
}



bool checkSlave( u_int32_t nlast, u_int32_t nserial, SOAData* sd, DomainInfo* di )
{
	if( nlast + sd->refresh < (u_int32_t) time( 0 ) )
	{
		di->kind = DomainInfo::Slave;
		return true;
	}

	return false;
}



bool checkMaster( u_int32_t nlast, u_int32_t nserial, SOAData* sd, DomainInfo* di )
{
	if( nserial != sd->serial )
	{
		di->kind = DomainInfo::Master;
		return true;
	}

	return false;
}
