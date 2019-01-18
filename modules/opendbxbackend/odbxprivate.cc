/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "odbxbackend.hh"



unsigned int odbx_host_index[2] = { 0, 0 };



bool OdbxBackend::connectTo( const vector<string>& hosts, QueryType type )
{
        int err;
        unsigned int h, i;
        int idx = odbx_host_index[type]++ % hosts.size();


        if( m_handle[type] != NULL )
        {
        	odbx_unbind( m_handle[type] );
        	odbx_finish( m_handle[type] );
        	m_handle[type] = NULL;
        }

        if( type == WRITE && getArg( "backend" ) == "sqlite" )
        {
        	g_log.log( m_myname + " Using same SQLite connection for reading and writing to '" + hosts[odbx_host_index[READ]] + "'", Logger::Notice );
        	m_handle[WRITE] = m_handle[READ];
        	return true;
        }

        for( i = 0; i < hosts.size(); i++ )
        {
        	h = ( idx + i ) % hosts.size();

        	if( ( err = odbx_init( &(m_handle[type]), getArg( "backend" ).c_str(), hosts[h].c_str(), getArg( "port" ).c_str() ) ) == ODBX_ERR_SUCCESS )
        	{
        		if( ( err = odbx_bind( m_handle[type], getArg( "database" ).c_str(), getArg( "username" ).c_str(), getArg( "password" ).c_str(), ODBX_BIND_SIMPLE ) ) == ODBX_ERR_SUCCESS )
        		{
        			g_log.log( m_myname + " Database connection (" + (type ? "write" : "read") + ") to '" + hosts[h] + "' succeeded", Logger::Notice );
        			return true;
        		}

        		g_log.log( m_myname + " Unable to bind to database on host " + hosts[h] + " - " + string( odbx_error( m_handle[type], err ) ),  Logger::Error );
        		continue;
        	}

        	g_log.log( m_myname + " Unable to connect to server on host " + hosts[h] + " - " + string( odbx_error( m_handle[type], err ) ),  Logger::Error );
        }

        m_handle[type] = NULL;
        return false;
}



bool OdbxBackend::execStmt( const char* stmt, unsigned long length, QueryType type )
{
        int err;


        DLOG( g_log.log( m_myname + " execStmt()", Logger::Debug ) );

        if( m_qlog ) { g_log.log( m_myname + " Query: " + stmt, Logger::Info ); }

        if( ( err = odbx_query( m_handle[type], stmt, length ) ) < 0 )
        {
        	g_log.log( m_myname + " execStmt: Unable to execute query - " + string( odbx_error( m_handle[type], err ) ),  Logger::Error );

        	if( err != -ODBX_ERR_PARAM && odbx_error_type( m_handle[type], err ) > 0 ) { return false; }   // ODBX_ERR_PARAM workaround
        	if( !connectTo( m_hosts[type], type ) ) { return false; }
        	if( odbx_query( m_handle[type], stmt, length ) < 0 ) { return false; }
        }

        if( type == WRITE ) { while( getRecord( type ) ); }

        return true;
}



bool OdbxBackend::getRecord( QueryType type )
{
        int err = 3;


        DLOG( g_log.log( m_myname + " getRecord()", Logger::Debug ) );

        do
        {
        	if( err < 0 )
        	{
        		g_log.log( m_myname + " getRecord: Unable to get next result - " + string( odbx_error( m_handle[type], err ) ),  Logger::Error );
        		throw( PDNSException( "Error: odbx_result() failed" ) );
        	}

        	if( m_result != NULL )
        	{
        		if( err == 3 )
        		{
        			if( ( err = odbx_row_fetch( m_result ) ) < 0 )
        			{
        				g_log.log( m_myname + " getRecord: Unable to get next row - " + string( odbx_error( m_handle[type], err ) ),  Logger::Error );
        				throw( PDNSException( "Error: odbx_row_fetch() failed" ) );
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

        				g_log.log( m_myname + " Values: " + fields,  Logger::Error );
#endif
        				return true;
        			}

        		}

        		odbx_result_free( m_result );
        		m_result = NULL;
        	}
        }
        while( ( err =  odbx_result( m_handle[type], &m_result, NULL, 0 ) ) != 0 );

        m_result = NULL;
        return false;
}



string OdbxBackend::escape( const string& str, QueryType type )
{
        int err;
        unsigned long len = sizeof( m_escbuf );


        DLOG( g_log.log( m_myname + " escape(string)", Logger::Debug ) );

        if( ( err = odbx_escape( m_handle[type], str.c_str(), str.size(), m_escbuf, &len ) ) < 0 )
        {
        	g_log.log( m_myname + " escape(string): Unable to escape string - " + string( odbx_error( m_handle[type], err ) ),  Logger::Error );

        	if( err != -ODBX_ERR_PARAM && odbx_error_type( m_handle[type], err ) > 0 ) { throw( runtime_error( "odbx_escape() failed" ) ); }   // ODBX_ERR_PARAM workaround
        	if( !connectTo( m_hosts[type], type ) ) { throw( runtime_error( "odbx_escape() failed" ) ); }
        	if( odbx_escape( m_handle[type], str.c_str(), str.size(), m_escbuf, &len ) < 0 ) { throw( runtime_error( "odbx_escape() failed" ) ); }
        }

        return string( m_escbuf, len );
}



bool OdbxBackend::getDomainList( const string& stmt, vector<DomainInfo>* list, bool (*check_fcn)(uint32_t,uint32_t,SOAData*,DomainInfo*) )
{
        const char* tmp;
        uint32_t nlast, nserial;

        SOAData sd;

        DLOG( g_log.log( m_myname + " getDomainList()", Logger::Debug ) );

        if( !execStmt( stmt.c_str(), stmt.size(), READ ) ) { return false; }
        if( !getRecord( READ ) ) { return false; }

        do
        {
        	DomainInfo di;
        	nlast = 0;
        	nserial = 0;
        	sd.serial = 0;
        	sd.refresh = 0;

        	if( ( tmp = odbx_field_value( m_result, 6 ) ) != NULL )
        	{
        		fillSOAData( string( tmp, odbx_field_length( m_result, 6 ) ), sd );
        	}

        	if( !sd.serial && ( tmp = odbx_field_value( m_result, 5 ) ) != NULL )
        	{
        		sd.serial = strtol( tmp, NULL, 10 );
        	}

        	if( ( tmp = odbx_field_value( m_result, 4 ) ) != NULL )
        	{
        		nserial = strtol( tmp, NULL, 10 );
        	}

        	if( ( tmp = odbx_field_value( m_result, 3 ) ) != NULL )
        	{
        		nlast = strtol( tmp, NULL, 10 );
        	}

        	if( (*check_fcn)( nlast, nserial, &sd, &di ) )
        	{
        		if( ( tmp = odbx_field_value( m_result, 2 ) ) != NULL )
        		{
        			vector<string> masters;
        			stringtok(masters, string( tmp, odbx_field_length( m_result, 2 )), ", \t" );
        			for(const auto& m : masters)
        			{
        				di.masters.emplace_back(m, 53);
        			}
        		}

        		if( ( tmp = odbx_field_value( m_result, 1 ) ) != NULL )
        		{
        			di.zone = DNSName( string(tmp, odbx_field_length( m_result, 1 )) );
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
        while( getRecord( READ ) );

        return true;
}



bool checkSlave( uint32_t nlast, uint32_t nserial, SOAData* sd, DomainInfo* di )
{
        if( nlast + sd->refresh < (uint32_t) time( 0 ) )
        {
        	di->kind = DomainInfo::Slave;
        	return true;
        }

        return false;
}



bool checkMaster( uint32_t nlast, uint32_t nserial, SOAData* sd, DomainInfo* di )
{
        if( nserial != sd->serial )
        {
        	di->kind = DomainInfo::Master;
        	return true;
        }

        return false;
}
