/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 * originally authored by Norbert Sendetzky
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
        		g_log.log( m_myname + " WARNING: Using deprecated opendbx-host parameter", Logger::Warning );
        		stringtok( m_hosts[READ], getArg( "host" ), ", " );
        		m_hosts[WRITE] = m_hosts[READ];
        	}
        	else
        	{
        		stringtok( m_hosts[READ], getArg( "host-read" ), ", " );
        		stringtok( m_hosts[WRITE], getArg( "host-write" ), ", " );
        	}

        	if( !connectTo( m_hosts[READ], READ ) ) { throw( PDNSException( "Fatal: Connecting to server for reading failed" ) ); }
        	if( !connectTo( m_hosts[WRITE], WRITE ) ) { throw( PDNSException( "Fatal: Connecting to server for writing failed" ) ); }
        }
        catch( std::exception& e )
        {
        	g_log.log( m_myname + " OdbxBackend(): Caught STL exception - " + e.what(),  Logger::Error );
        	throw( PDNSException( "Fatal: STL exception" ) );
        }
}



OdbxBackend::~OdbxBackend()
{
        odbx_unbind( m_handle[WRITE] );
        odbx_unbind( m_handle[READ] );

        odbx_finish( m_handle[WRITE] );
        odbx_finish( m_handle[READ] );
}



bool OdbxBackend::getDomainInfo( const DNSName& domain, DomainInfo& di, bool getSerial )
{
        const char* tmp;


        try
        {
        	DLOG( g_log.log( m_myname + " getDomainInfo()", Logger::Debug ) );

        	string stmt = getArg( "sql-zoneinfo" );
        	string& stmtref = strbind( ":name", escape( domain.makeLowerCase().toStringRootDot(), READ ), stmt );

        	if( !execStmt( stmtref.c_str(), stmtref.size(), READ ) ) { return false; }
        	if( !getRecord( READ ) ) { return false; }

        	do
        	{
        		di.id = 0;
        		di.zone.clear();
        		di.masters.clear();
        		di.last_check = 0;
        		di.notified_serial = 0;
        		di.kind = DomainInfo::Native;
        		di.backend = this;
        		di.serial = 0;

        		if( getSerial && ( tmp = odbx_field_value( m_result, 6 ) ) != NULL )
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
        			vector<string> masters;
        			stringtok(masters, string( tmp, odbx_field_length( m_result, 3 ) ), ", \t");
        			for(const auto& m : masters)
        			{
        				di.masters.emplace_back(m, 53);
        			}
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
        			di.zone = DNSName(string( tmp, odbx_field_length( m_result, 1 ) ));
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
        	g_log.log( m_myname + " getDomainInfo: Caught STL std::exception - " + e.what(),  Logger::Error );
        	return false;
        }

        return true;
}



bool OdbxBackend::getSOA( const DNSName& domain, SOAData& sd )
{
        const char* tmp;


        try
        {
        	DLOG( g_log.log( m_myname + " getSOA()", Logger::Debug ) );

        	string stmt = getArg( "sql-lookupsoa" );
        	string& stmtref = strbind( ":name", escape( domain.makeLowerCase().toStringRootDot(), READ ), stmt );

        	if( !execStmt( stmtref.c_str(), stmtref.size(), READ ) ) { return false; }
        	if( !getRecord( READ ) ) { return false; }

        	do
        	{
        		sd.qname = domain;
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
        			sd.nameserver = DNSName(arg()["default-soa-name"]);
        		}

        		if( sd.hostmaster.empty() )
        		{
        			sd.hostmaster = DNSName("hostmaster") + DNSName(domain);
        		}

        		sd.db = this;
        	}
        	while( getRecord( READ ) );
        }
        catch( std::exception& e )
        {
        	g_log.log( m_myname + " getSOA: Caught STL exception - " + e.what(),  Logger::Error );
        	return false;
        }

        return true;
}



bool OdbxBackend::list( const DNSName& target, int zoneid, bool include_disabled )
{
        try
        {
        	DLOG( g_log.log( m_myname + " list()", Logger::Debug ) );

        	m_qname.clear();
        	m_result = NULL;

        	int len = snprintf( m_buffer, sizeof( m_buffer ), "%d", zoneid );

        	if( len < 0 )
        	{
        		g_log.log( m_myname + " list: Unable to convert zone id to string - format error",  Logger::Error );
        		return false;
        	}

        	if( len > static_cast<int>(sizeof( m_buffer )) - 1 )
        	{
        		g_log.log( m_myname + " list: Unable to convert zone id to string - insufficient buffer space",  Logger::Error );
        		return false;
        	}

        	string stmt = getArg( "sql-list" );
        	string& stmtref = strbind( ":id", string( m_buffer, len ), stmt );

        	if( !execStmt( stmtref.c_str(), stmtref.size(), READ ) ) { return false; }
        }
        catch( std::exception& e )
        {
        	g_log.log( m_myname + " list: Caught STL exception - " + e.what(),  Logger::Error );
        	return false;
        }

        return true;
}



void OdbxBackend::lookup( const QType& qtype, const DNSName& qname, int zoneid, DNSPacket* dnspkt )
{
        try
        {
        	DLOG( g_log.log( m_myname + " lookup()", Logger::Debug ) );

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

        		int len = snprintf( m_buffer, sizeof( m_buffer ), "%d", zoneid );

        		if( len < 0 )
        		{
        			g_log.log( m_myname + " lookup: Unable to convert zone id to string - format error",  Logger::Error );
        			throw( DBException( "Error: Libc error" ) );
        		}

        		if( len > static_cast<int>(sizeof( m_buffer )) - 1 )
        		{
        			g_log.log( m_myname + " lookup: Unable to convert zone id to string - insufficient buffer space",  Logger::Error );
        			throw( DBException( "Error: Libc error" ) );
        	}

        		stmtref = strbind( ":id", string( m_buffer, len ), stmtref );
        	}

        	stmtref = strbind( ":name", escape( qname.makeLowerCase().toStringRootDot(), READ ), stmtref );

        	if( !execStmt( stmtref.c_str(), stmtref.size(), READ ) )
        	{
        		throw( DBException( "Error: DB statement failed" ) );
        	}
        }
        catch( std::exception& e )
        {
        	g_log.log( m_myname + " lookup: Caught STL exception - " + e.what(),  Logger::Error );
        	throw( DBException( "Error: STL exception" ) );
        }
}



bool OdbxBackend::get( DNSResourceRecord& rr )
{
        const char* tmp;
        string priority;

        try
        {
        	DLOG( g_log.log( m_myname + " get()", Logger::Debug ) );

        	if( getRecord( READ ) )
        	{

        		rr.content = "";
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
        			rr.qname = DNSName( string(tmp, odbx_field_length( m_result, 1 ) ));
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
        			priority = string( tmp, odbx_field_length( m_result, 4 ) );
        		}

        		if( ( tmp = odbx_field_value( m_result, 5 ) ) != NULL )
        		{
        			rr.content = string( tmp, odbx_field_length( m_result, 5 ) );
        		}

        		if (rr.qtype==QType::MX || rr.qtype==QType::SRV)
        			rr.content = priority + " " + rr.content;

        		return true;
        	}
        }
        catch( std::exception& e )
        {
        	g_log.log( m_myname + " get: Caught STL exception - " + e.what(),  Logger::Error );
        	return false;
        }

        return false;
}


void OdbxBackend::setFresh( uint32_t domain_id )
{
        int len;


        try
        {
        	DLOG( g_log.log( m_myname + " setFresh()", Logger::Debug ) );

        	if( !m_handle[WRITE] && !connectTo( m_hosts[WRITE], WRITE ) )
        	{
        		g_log.log( m_myname + " setFresh: Master server is unreachable",  Logger::Error );
        		throw( DBException( "Error: Server unreachable" ) );
        	}

        	len = snprintf( m_buffer, sizeof( m_buffer ), getArg( "sql-update-lastcheck" ).c_str(), time( 0 ), domain_id );

        	if( len < 0 )
        	{
        		g_log.log( m_myname + " setFresh: Unable to insert values into statement '" + getArg( "sql-update-lastcheck" ) + "' - format error",  Logger::Error );
        		throw( DBException( "Error: Libc error" ) );
        	}

        	if( len > static_cast<int>(sizeof( m_buffer )) - 1 )
        	{
        		g_log.log( m_myname + " setFresh: Unable to insert values into statement '" + getArg( "sql-update-lastcheck" ) + "' - insufficient buffer space",  Logger::Error );
        		throw( DBException( "Error: Libc error" ) );
        	}

        	if( !execStmt( m_buffer, len, WRITE ) )
        	{
        		throw( DBException( "Error: DB statement failed" ) );
        	}
        }
        catch ( std::exception& e )
        {
        	g_log.log( m_myname + " setFresh: Caught STL exception - " + e.what(),  Logger::Error );
        	throw( DBException( "Error: STL exception" ) );
        }
}



void OdbxBackend::setNotified( uint32_t domain_id, uint32_t serial )
{
        try
        {
        	DLOG( g_log.log( m_myname + " setNotified()", Logger::Debug ) );

        	if( !m_handle[WRITE] && !connectTo( m_hosts[WRITE], WRITE ) )
        	{
        		g_log.log( m_myname + " setFresh: Master server is unreachable",  Logger::Error );
        		throw( DBException( "Error: Server unreachable" ) );
        	}

        	int len = snprintf( m_buffer, sizeof( m_buffer ), getArg( "sql-update-serial" ).c_str(), serial, domain_id );

        	if( len < 0 )
        	{
        		g_log.log( m_myname + " setNotified: Unable to insert values into statement '" + getArg( "sql-update-serial" ) + "' - format error",  Logger::Error );
        		throw( DBException( "Error: Libc error" ) );
        	}

        	if( len > static_cast<int>(sizeof( m_buffer )) - 1 )
        	{
        		g_log.log( m_myname + " setNotified: Unable to insert values into statement '" + getArg( "sql-update-serial" ) + "' - insufficient buffer space",  Logger::Error );
        		throw( DBException( "Error: Libc error" ) );
        	}

        	if( !execStmt( m_buffer, len, WRITE ) )
        	{
        		throw( DBException( "Error: DB statement failed" ) );
        	}
        }
        catch ( std::exception& e )
        {
        	g_log.log( m_myname + " setNotified: Caught STL exception - " + e.what(),  Logger::Error );
        	throw( DBException( "Error: STL exception" ) );
        }
}



void OdbxBackend::getUnfreshSlaveInfos( vector<DomainInfo>* unfresh )
{
        try
        {
        	DLOG( g_log.log( m_myname + " getUnfreshSlaveInfos()", Logger::Debug ) );

        	if( unfresh == NULL )
        	{
        		g_log.log( m_myname + " getUnfreshSlaveInfos: invalid parameter - NULL pointer",  Logger::Error );
        		return;
        	}

        	getDomainList( getArg( "sql-infoslaves" ), unfresh, &checkSlave );
        }
        catch ( std::exception& e )
        {
        	g_log.log( m_myname + " getUnfreshSlaveInfo: Caught STL exception - " + e.what(),  Logger::Error );
        }
}



void OdbxBackend::getUpdatedMasters( vector<DomainInfo>* updated )
{
        try
        {
        	DLOG( g_log.log( m_myname + " getUpdatedMasters()", Logger::Debug ) );

        	if( updated == NULL )
        	{
        		g_log.log( m_myname + " getUpdatedMasters: invalid parameter - NULL pointer",  Logger::Error );
        		return;
        	}

        	getDomainList( getArg( "sql-infomasters" ), updated, &checkMaster );
        }
        catch ( std::exception& e )
        {
        	g_log.log( m_myname + " getUpdatedMasters: Caught STL exception - " + e.what(),  Logger::Error );
        }
}



bool OdbxBackend::superMasterBackend( const string& ip, const DNSName& domain, const vector<DNSResourceRecord>& set, string *nameserver, string* account, DNSBackend** ddb )
{
        try
        {
        	DLOG( g_log.log( m_myname + " superMasterBackend()", Logger::Debug ) );

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
        	g_log.log( m_myname + " superMasterBackend: Caught STL exception - " + e.what(),  Logger::Error );
        	return false;
        }

        return false;
}



bool OdbxBackend::createSlaveDomain( const string& ip, const DNSName& domain, const string &nameserver, const string& account )
{
        try
        {
        	DLOG( g_log.log( m_myname + " createSlaveDomain()", Logger::Debug ) );

        	if( !m_handle[WRITE] && !connectTo( m_hosts[WRITE], WRITE ) )
        	{
        		g_log.log( m_myname + " createSlaveDomain: Master server is unreachable",  Logger::Error );
        		return false;
        	}

        	int len = snprintf( m_buffer, sizeof( m_buffer ), getArg( "sql-insert-slave" ).c_str(), escape( domain.makeLowerCase().toStringRootDot(), WRITE ).c_str(),
        		escape( ip, WRITE ).c_str(), escape( account, WRITE ).c_str() );

        	if( len < 0 )
        	{
        		g_log.log( m_myname + " createSlaveDomain: Unable to insert values in statement '" + getArg( "sql-insert-slave" ) + "' - format error",  Logger::Error );
        		return false;
        	}

        	if( len > static_cast<int>(sizeof( m_buffer )) - 1 )
        	{
        		g_log.log( m_myname + " createSlaveDomain: Unable to insert values in statement '" + getArg( "sql-insert-slave" ) + "' - insufficient buffer space",  Logger::Error );
        		return false;
        	}

        	if( !execStmt( m_buffer, len, WRITE ) ) { return false; }
        }
        catch ( std::exception& e )
        {
        	g_log.log( m_myname + " createSlaveDomain: Caught STL exception - " + e.what(),  Logger::Error );
        	return false;
        }

        return true;
}



bool OdbxBackend::feedRecord( const DNSResourceRecord& rr, const DNSName& ordername, bool ordernameIsNSEC3 )
{
        try
        {
        	DLOG( g_log.log( m_myname + " feedRecord()", Logger::Debug ) );

        	if( !m_handle[WRITE] && !connectTo( m_hosts[WRITE], WRITE ) )
        	{
        		g_log.log( m_myname + " feedRecord: Master server is unreachable",  Logger::Error );
        		return false;
        	}

        	unsigned int priority=0;
        	string content(rr.content);

        	if(rr.qtype == QType::MX || rr.qtype == QType::SRV) {
        		priority=pdns_stou(content);
        		string::size_type pos = content.find_first_not_of("0123456789");
        		if(pos != string::npos)
        			boost::erase_head(content, pos);
        		trim_left(content);
        	}

        	int len = snprintf( m_buffer, sizeof( m_buffer ), getArg( "sql-insert-record" ).c_str(), rr.domain_id,
        		escape( rr.qname.makeLowerCase().toStringRootDot(), WRITE ).c_str(), rr.qtype.getName().c_str(), rr.ttl, priority,
        		escape( content, WRITE ).c_str() );

        	if( len < 0 )
        	{
        		g_log.log( m_myname + " feedRecord: Unable to insert values in statement '" + getArg( "sql-insert-record" ) + "' - format error",  Logger::Error );
        		return false;
        	}

        	if( len > static_cast<int>(sizeof( m_buffer )) - 1 )
        	{
        		g_log.log( m_myname + " feedRecord: Unable to insert values in statement '" + getArg( "sql-insert-record" ) + "' - insufficient buffer space",  Logger::Error );
        		return false;
        	}

        	if( !execStmt( m_buffer, len, WRITE ) ) { return false; }
        }
        catch ( std::exception& e )
        {
        	g_log.log( m_myname + " feedRecord: Caught STL exception - " + e.what(),  Logger::Error );
        	return false;
        }

        return true;
}



bool OdbxBackend::startTransaction( const DNSName& domain, int zoneid )
{
        try
        {
        	DLOG( g_log.log( m_myname + " startTransaction()", Logger::Debug ) );

        	if( !m_handle[WRITE] && !connectTo( m_hosts[WRITE], WRITE ) )
        	{
        		g_log.log( m_myname + " startTransaction: Master server is unreachable",  Logger::Error );
        		return false;
        	}

        	string stmtref =  getArg( "sql-transactbegin" );
        	if( !execStmt( stmtref.c_str(), stmtref.size(), WRITE ) ) { return false; }
        	int len = snprintf( m_buffer, sizeof( m_buffer ), "%d", zoneid );

        	if( len < 0 )
        	{
        		g_log.log( m_myname + " startTransaction: Unable to convert zone id to string - format error",  Logger::Error );
        		return false;
        	}

        	if( len > static_cast<int>(sizeof( m_buffer )) - 1 )
        	{
        		g_log.log( m_myname + " startTransaction: Unable to convert zone id to string - insufficient buffer space",  Logger::Error );
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
        	g_log.log( m_myname + " startTransaction: Caught STL exception - " + e.what(),  Logger::Error );
        	return false;
        }

        return true;
}



bool OdbxBackend::commitTransaction()
{
        try
        {
        	DLOG( g_log.log( m_myname + " commitTransaction()", Logger::Debug ) );

        	if( !m_handle[WRITE] && !connectTo( m_hosts[WRITE], WRITE ) )
        	{
        		g_log.log( m_myname + " commitTransaction: Master server is unreachable",  Logger::Error );
        		return false;
        	}

        	const string& stmt = getArg( "sql-transactend" );
        	if( !execStmt( stmt.c_str(), stmt.size(), WRITE ) ) { return false; }
        }
        catch ( std::exception& e )
        {
        	g_log.log( m_myname + " commitTransaction: Caught STL exception - " + e.what(),  Logger::Error );
        	return false;
        }

        return true;
}



bool OdbxBackend::abortTransaction()
{
        try
        {
        	DLOG( g_log.log( m_myname + " abortTransaction()", Logger::Debug ) );

        	if( !m_handle[WRITE] && !connectTo( m_hosts[WRITE], WRITE ) )
        	{
        		g_log.log( m_myname + " abortTransaction: Master server is unreachable",  Logger::Error );
        		return false;
        	}

        	const string& stmt = getArg( "sql-transactabort" );
        	if( !execStmt( stmt.c_str(), stmt.size(), WRITE ) ) { return false; }
        }
        catch ( std::exception& e )
        {
        	g_log.log( m_myname + " abortTransaction: Caught STL exception - " + e.what(),  Logger::Error );
        	return false;
        }

        return true;
}
