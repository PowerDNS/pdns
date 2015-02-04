/*
 * File: geosqlbackend.cpp
 *
 * Description: This file is part of the GeoSQL backend for PowerDNS
 *
 * Copyright (C) Shin Sterneck 2013-2018 (email: shin at sterneck dot asia)
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

#include "geosqlbackend.hh"

/**
 * @brief GeoSqlBackend Constructor
 * @param suffix Specifies configuration suffix for PowerDNS
 */
GeoSqlBackend::GeoSqlBackend ( const string &suffix )
{
    // load configuration
    setArgPrefix ( "geosql" + suffix );
    rrs = new vector<DNSResourceRecord>();
    geosqlRrs = new set<string>();

    try {
        // GeoIP Database Connectivity
        geoip_db = new SMySQL ( getArg ( "geo-database" ),
                                getArg ( "geo-host" ),
                                getArgAsNum ( "geo-port" ),
                                getArg ( "geo-socket" ),
                                getArg ( "geo-username" ),
                                getArg ( "geo-password" ),
                                getArg ( "geo-group" ),
                                mustDo ( "geo-innodb-read-committed" ),
                                getArgAsNum ( "geo-timeout" ) );

        // PowerDNS Database Connectivity
        pdns_db = new SMySQL ( getArg ( "pdns-database" ),
                               getArg ( "pdns-host" ),
                               getArgAsNum ( "pdns-port" ),
                               getArg ( "pdns-socket" ),
                               getArg ( "pdns-username" ),
                               getArg ( "pdns-password" ),
                               getArg ( "pdns-group" ),
                               mustDo ( "pdns-innodb-read-committed" ),
                               getArgAsNum ( "pdns-timeout" ) );

    } catch ( SSqlException &e ) {
        L << Logger::Debug << "geosql " << "DB Connection failed: " << e.txtReason() << endl;
        throw PDNSException ( "geosql DB Connection failed: " + e.txtReason() );
    }

    geosqlenabled_stmt = pdns_db->prepare ( getArg ( "sql-pdns-lookup-geosqlenabled" ), 1 );
    region_stmt = geoip_db->prepare ( getArg ( "sql-geo-lookup-region" ), 1 );
    cc_stmt_any = pdns_db->prepare ( getArg ( "sql-pdns-lookuptype-any" ), 3 );
    cc_stmt = pdns_db->prepare ( getArg ( "sql-pdns-lookuptype" ), 4 );

    enable_cache = true;
    cacheThread = new boost::thread ( &GeoSqlBackend::refresh_cache, this );

}

void GeoSqlBackend::refresh_cache ()
{

    boost::regex re ( "^(.*)\\..*\\." + getArg ( "domain-suffix" ) + "$" );

    while ( enable_cache ) {

        try {
            SSqlStatement::result_t result;
            cache_mutex.lock();

            geosqlenabled_stmt->bind ( "like", string ( "%" + getArg ( "domain-suffix" ) ) );
            geosqlenabled_stmt->execute()->getResult ( result )->reset();

            // re-populate cache
            if ( result.size() > 0 ) {

                // clear cache
                geosqlRrs->clear();

                // remove geosql country/region and suffix and store in simple cache set
                // sets will ensure uniquenes
                for ( unsigned int i = 0; i < result.size(); i++ ) {
                    boost::smatch matches;

                    if ( boost::regex_match ( result[i][0], matches, re ) ) {
                        geosqlRrs->insert ( string ( matches[1] ) );
                    }
                }

            }

            cache_mutex.unlock();

            L << Logger::Debug << "geosql " << "Cache updated with " << geosqlRrs->size() << " enabled records" << endl;

        } catch ( SSqlException &e ) {
            cache_mutex.unlock();
            L << Logger::Error << "geosql " << "DB Connection failed: " << e.txtReason() << endl;
        }

        // wait X seconds before continuing
        boost::this_thread::sleep ( boost::posix_time::seconds ( getArgAsNum ( "geo-cache-ttl" ) ) );
    }

}

/**
 * @brief Function for looking up the DNS records and storing the result into a vector.
 * @param qtype The DNS query type
 * @param qdomain The DNS domain name
 * @param pkt_p The DNS Packet
 * @param zoneId The Zone ID
 */
void GeoSqlBackend::lookup ( const QType &qtype, const DNSName &qdomain, DNSPacket *pkt_p, int zoneId )
{
    ComboAddress remoteIp;

    cache_mutex.lock();

    try {
        //check if qdomain is a registered geosql enabled record, if not skip the whole backend
        if ( geosqlRrs->find ( qdomain.toStringNoDot() ) != geosqlRrs->end() ) {
            cache_mutex.unlock();

            L << Logger::Debug << "geosql " << "Handling Query Request: '" << qdomain.toStringNoDot() << ":" << qtype.getName() << "'" << endl;

            //check for ECS data and use it if found
            if ( pkt_p->hasEDNSSubnet() ) {
                remoteIp = pkt_p->getRealRemote().getNetwork();

            } else {
                remoteIp = pkt_p->getRemote();
            }

            // get region and dns records for that region
            sqlregion region;

            if ( getRegionForIP ( remoteIp, region ) ) {
                getGeoDnsRecords ( qtype, qdomain.toStringNoDot(), region );
            }

        } else {
            cache_mutex.unlock();
            L << Logger::Debug << "geosql " << "Skipping Query request: '" << qdomain.toStringNoDot() << "' not a geosql enabled record" << endl;
        }

    } catch ( SSqlException &e ) {
        cache_mutex.unlock();
        throw PDNSException ( "geosql lookup failed " + e.txtReason() );
    }
}

/**
 * @brief Function used by PowerDNS to retrieve the records
 * @param rr Reference containing the individual DNSResourceRecord
 * @return true as long as there are records left in the vector filled by the lookup() function
 */
bool GeoSqlBackend::get ( DNSResourceRecord &rr )
{
    if ( rrs->size() > 0 ) {
        rr = rrs->at ( rrs->size() - 1 );
        rrs->pop_back();
        return true;
    }

    return false;
}

/**
 * @brief Function to get region
 * @param ip The source IP address from the request packet
 * @param returned_region contains the identifed region information
 * @return bool success or failure indicator
 */
bool GeoSqlBackend::getRegionForIP ( ComboAddress &ip, sqlregion &returned_region )
{
    bool foundCountry = false;

    std::vector<boost::any> sqlResponseData;

    region_stmt->bind ( "ip", ip.toString() );

    if ( getSqlData ( region_stmt, sqlResponseData, SQL_RESP_TYPE_REGION ) ) {
        sqlregion region = boost::any_cast<sqlregion> ( sqlResponseData.at ( 0 ) );
        boost::to_lower ( region.regionname );
        boost::to_lower ( region.countrycode );
        returned_region = region;
        foundCountry = true;
    }

    if ( foundCountry ) {
        string logentry = "Identified as: '" + returned_region.countrycode;

        if ( !returned_region.regionname.empty() ) {
            logentry.append ( "|" + returned_region.regionname + "'" );

        } else {
            logentry.append ( "'" );
        }

        L << Logger::Debug << "geosql " << logentry << endl;

    } else {
        L << Logger::Debug << "geosql " << "No Region Found" << endl;
    }

    return foundCountry;
}

/**
 * @brief Function to retrieve the DNS records according to the geographic location (assigned by region field)
 * @param type the DNS query type
 * @param qdomain the DNS domain name
 * @param region Specifies the records for the supplied region
 * @return bool success of failure indicator
 */
bool GeoSqlBackend::getGeoDnsRecords ( const QType &type, const string &qdomain, const sqlregion &region )
{
    bool foundRecords = false;
    std::vector<boost::any> sqlResponseData;

    bool typeAny = false;

    if ( type.getCode() == QType::ANY || type.getCode() == QType::SOA ) {
        typeAny = true;
    }

    // get country specific records
    if ( !region.countrycode.empty() ) {
        string removeString =  string ( "." + region.countrycode + "." + getArg ( "domain-suffix" ) );

        if ( typeAny ) {
            cc_stmt_any->bind ( "removeString1" , removeString )
            ->bind ( "removeString2" , removeString )
            ->bind ( "name" , string ( qdomain + removeString ) );

            foundRecords = getSqlData ( cc_stmt_any, sqlResponseData, SQL_RESP_TYPE_DNSRR );

        } else {
            cc_stmt->bind ( "removeString1" , removeString )
            ->bind ( "removeString2" , removeString )
            ->bind ( "name" , string ( qdomain + removeString ) )
            ->bind ( "type" , type.getName() );

            foundRecords = getSqlData ( cc_stmt, sqlResponseData, SQL_RESP_TYPE_DNSRR );

        }
    }

    // if no country records found, get region specific records (last resort)
    if ( !foundRecords && !region.regionname.empty() ) {
        string removeString =  string ( "." + region.regionname + "." + getArg ( "domain-suffix" ) );

        if ( typeAny ) {
            cc_stmt_any->bind ( "removeString1" , removeString )
            ->bind ( "removeString2" , removeString )
            ->bind ( "name" , string ( qdomain + removeString ) );

            foundRecords = getSqlData ( cc_stmt_any, sqlResponseData, SQL_RESP_TYPE_DNSRR );

        } else {
            cc_stmt->bind ( "removeString1" , removeString )
            ->bind ( "removeString2" , removeString )
            ->bind ( "name" , string ( qdomain + removeString ) )
            ->bind ( "type" , type.getName() );

            foundRecords = getSqlData ( cc_stmt, sqlResponseData, SQL_RESP_TYPE_DNSRR );

        }
    }

    if ( foundRecords ) {
        DNSResourceRecord record;
        record.auth = 1;

        for ( int i = 0; i < sqlResponseData.size(); i++ ) {
            record = boost::any_cast<DNSResourceRecord> ( sqlResponseData.at ( i ) );
            rrs->push_back ( record );
        }

    }

    return foundRecords;
}

/**
 * @brief unified way of handling sql queries and storing the result into a vector
 * @param conn OpenDBX database connection object
 * @param sqlStatement SQL Satement to be executed
 * @param sqlResponseData Vector containing the database response records
 * @param sqlResponseType Specified what type of response is expected (SQL_RESP_TYPE_REGION or SQL_RESP_TYPE_DNSRR)
 * @return bool sucess of failure indicator
 */
bool GeoSqlBackend::getSqlData ( SSqlStatement *sqlStatement, std::vector<boost::any> &sqlResponseData, int sqlResponseType )
{

    bool dataAvailable = false;
    sqlResponseData.clear();

    switch ( sqlResponseType ) {
        case SQL_RESP_TYPE_DNSRR: {

                try {

                    DNSResourceRecord row;
                    SSqlStatement::result_t result;

                    cache_mutex.lock();
                    sqlStatement->execute()
                    ->getResult ( result )
                    ->reset();

                    cache_mutex.unlock();

                    if ( !result.empty() ) {

                        for ( int i = 0 ; i < result.size(); i++ ) {
                            row.qname = DNSName ( result[i][0] );
                            row.qtype = string ( result[i][1] );

                            if ( row.qtype == QType::MX || row.qtype == QType::SRV ) {
                                row.content = string ( result[i][4]  + " " + string ( result[i][2] ) );

                            } else {
                                row.content = string ( result[i][2] );
                            }

                            row.ttl = pdns_stou ( result[i][3] );

                            sqlResponseData.push_back ( row );

                            L << Logger::Debug << "Result: " << result[i][0] << " : " << string ( result[i][1] ) << " : " << string ( result[i][2] ) << " : "  << result[i][4] << endl;
                        }


                        dataAvailable = true;

                    }

                } catch ( std::exception &e ) {
                    cache_mutex.unlock();
                    throw PDNSException ( "geosql Error while retrieving DNS RR records from the database: " );
                }

                break;

            }

        case SQL_RESP_TYPE_REGION: {
                sqlregion row;
                row.countrycode = "";
                row.regionname = "";

                try {

                    SSqlStatement::result_t result;
                    cache_mutex.lock();

                    sqlStatement->execute()
                    ->getResult ( result )
                    ->reset();

                    cache_mutex.unlock();

                    if ( !result.empty() ) {
                        row.countrycode = string ( result[0][0] );
                        row.regionname = string ( result[0][1] );
                        sqlResponseData.push_back ( row );

                        dataAvailable = true;
                    }

                } catch ( std::exception &e ) {
                    cache_mutex.unlock();
                    throw PDNSException ( "geosql Error while retrieving region records from the database: " );
                }

                break;
            }
    }
    
    return dataAvailable;
}

/**
 * @brief Function used by PowerDNS to retrieve the SOA record for a domain. In this backend we do not support SOA records.
 * @param name The DNS domain name
 * @param soadata reference to the SOA data
 * @param p the DNS packet
 */
bool GeoSqlBackend::getSOA ( const DNSName &name, SOAData &soadata, DNSPacket *p )
{
    return false;
}

/**
 * @brief Used by PowerDNS for zone transfer purposes
 * @param target Stores the DNS name
 * @param domain_id The Domain ID for the domain in question
 * @param include_disabled Specified whether disabled domains should be included in the response
 * @return false (no support for zone transfers in this backend, use main zone for this purpose for now)
 */
bool GeoSqlBackend::list ( const DNSName &target, int domain_id, bool include_disabled )
{
    return false;
}

/**
 * @brief GeoSQL class destructor
 */
GeoSqlBackend::~GeoSqlBackend()
{
    L << Logger::Debug << "Destroying Backend geosql" << endl;

    cacheThread->interrupt();
    cacheThread->join();

    delete cacheThread;
    cacheThread = NULL;

    // general cleanup
    delete geoip_db;
    delete pdns_db;
    delete rrs;
    delete geosqlRrs;
    delete region_stmt;
    delete cc_stmt_any;
    delete cc_stmt;
    delete geosqlenabled_stmt;

    geoip_db = NULL;
    pdns_db = NULL;
    rrs = NULL;
    geosqlRrs = NULL;
    cc_stmt = NULL;
    cc_stmt_any = NULL;
    region_stmt = NULL;
    geosqlenabled_stmt = NULL;
}

/**
 * @class GeoSqlFactory
 * @author Shin Sterneck
 * @date 2013
 * @file geosqlbackend.cpp
 * @brief The main BackendFactory for GeoSqlBackend
 */
class GeoSqlFactory : public BackendFactory
{
    public:

        GeoSqlFactory() : BackendFactory ( "geosql" ) {
        }

        /**
         * @brief declares configuration options
         * @param suffix specified the configuration suffix used by PowerDNS
         */
        void declareArguments ( const string &suffix ) {
            // GeoSQL configuration part
            declare ( suffix, "domain-suffix", "Set the domain suffix for GeoSQL zones without prefixed 'dot' character", "geosql" );
            declare ( suffix, "geo-cache-ttl", "Set how often the geosql enabled records cache should be refreshed, in seconds", "60" );

            // GeoDB DB Connection part
            declare ( suffix, "geo-host", "The GeoIP Database server IP/FQDN", "localhost" );
            declare ( suffix, "geo-port", "The GeoIP Database server Port", "3306" );
            declare ( suffix, "geo-socket", "The GeoIP Database server socket", "" );
            declare ( suffix, "geo-database", "The GeoIP Database name", "geoip" );
            declare ( suffix, "geo-username", "The GeoIP Database username", "geoip" );
            declare ( suffix, "geo-password", "The GeoIP Database password", "geoip" );
            declare ( suffix, "geo-group", "The GeoIP Database MySQL 'group' to connect as", "client" );
            declare ( suffix, "geo-timeout", "The GeoIP Database transaction timeout in seconds", "10" );
            declare ( suffix, "geo-innodb-read-committed", "Use InnoDB READ-COMMITTED transaction isolation level for the GeoIP Database", "true" );

            // PowerDNS DB Connection part
            declare ( suffix, "pdns-host", "The PowerDNS Database server IP/FQDN", "localhost" );
            declare ( suffix, "pdns-port", "The PowerDNS Database server Port", "3306" );
            declare ( suffix, "pdns-socket", "The PowerDNS Database server socket", "" );
            declare ( suffix, "pdns-database", "The PowerDNS Database name", "pdns" );
            declare ( suffix, "pdns-username", "The PowerDNS Database username", "pdns" );
            declare ( suffix, "pdns-password", "The PowerDNS Database password", "pdns" );
            declare ( suffix, "pdns-group", "The PowerDNS Database MySQL 'group' to connect as", "client" );
            declare ( suffix, "pdns-timeout", "The PowerDNS Database transaction timeout in seconds", "10" );
            declare ( suffix, "pdns-innodb-read-committed", "Use InnoDB READ-COMMITTED transaction isolation level for the PowerDNS Database", "true" );

            // SQL Statements
            declare ( suffix, "sql-pdns-lookuptype", "SQL Statement to retrieve RR types such as A,CNAME,TXT or MX records", "select replace(name, ?,''), type , replace(content,?,''), ttl, prio from records where name=? and type=? and disabled=0;" );
            declare ( suffix, "sql-pdns-lookuptype-any", "SQL Statement to retrieve the ANY RR type requests", "select replace(name, ?,''), type, replace(content,?,''), ttl, prio from records where name=? and type != 'SOA' and disabled=0;" );
            declare ( suffix, "sql-geo-lookup-region", "SQL Statement to lookup the REGION and Country Code by source IP address", "select cc,regionname from lookup where MBRCONTAINS(ip_poly, POINTFROMWKB(POINT(INET_ATON( ? ), 0)));" );
            declare ( suffix, "sql-pdns-lookup-geosqlenabled", "SQL Statement to lookup domains, which are enabled for geosql.", "select distinct name from records where name like ?;" );
        }

        /**
         * @brief function to make DNSBackend as documented by PowerDNS
         * @param suffix specified configuration suffix used by PowerDNS
         * @return GeoSqlBackend object
         */
        DNSBackend *make ( const string &suffix ) {
            return new GeoSqlBackend ( suffix );
        }
};

/**
 * @class GeoSqlLoader
 * @author Shin Sterneck
 * @brief The GeoSsqlLoader class to help load the backend itself
 */
class GeoSqlLoader
{
    public:

        /**
         * @brief The backend loader
         */
        GeoSqlLoader() {
            BackendMakers().report ( new GeoSqlFactory );
        }

};

static GeoSqlLoader geosqlloader;
