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
#include <string>
#include <cstdlib>
#include <sstream>
#include <sys/time.h>
#include "pdns/dns.hh"
#include "pdns/utility.hh"
#include "pdns/dnspacket.hh"
#include "pdns/dnsbackend.hh"
#include "pdns/pdnsexception.hh"
#include "pdns/arguments.hh"
#include "pdns/logger.hh"
#include <odbx.h>


#ifndef ODBXBACKEND_HH
#define ODBXBACKEND_HH


#define BUFLEN 512


using std::string;
using std::vector;



bool checkSlave( uint32_t last, uint32_t notified, SOAData* sd, DomainInfo* di );
bool checkMaster( uint32_t last, uint32_t notified, SOAData* sd, DomainInfo* di );


class OdbxBackend : public DNSBackend
{
        enum QueryType { READ, WRITE };

        string m_myname;
        DNSName m_qname;
        int m_default_ttl;
        bool m_qlog;
        odbx_t* m_handle[2];
        odbx_result_t* m_result;
        char m_escbuf[BUFLEN];
        char m_buffer[2*BUFLEN];
        vector<string> m_hosts[2];

        string escape( const string& str, QueryType type );
        bool connectTo( const vector<string>& host, QueryType type );
        bool getDomainList( const string& query, vector<DomainInfo>* list, bool (*check_fcn)(uint32_t,uint32_t,SOAData*,DomainInfo*) );
        bool execStmt( const char* stmt, unsigned long length, QueryType type );
        bool getRecord( QueryType type );


public:

        OdbxBackend( const string& suffix="" );
        ~OdbxBackend();

        void lookup( const QType& qtype, const DNSName& qdomain, int zoneid, DNSPacket* p = nullptr ) override;
        bool getSOA( const DNSName& domain, SOAData& sd ) override;
        bool list( const DNSName& target, int domain_id, bool include_disabled=false ) override;
        bool get( DNSResourceRecord& rr ) override;

        bool startTransaction( const DNSName& domain, int domain_id ) override;
        bool commitTransaction() override;
        bool abortTransaction() override;

        bool getDomainInfo( const DNSName& domain, DomainInfo& di, bool getSerial=true ) override;
        bool feedRecord( const DNSResourceRecord& rr, const DNSName& ordername, bool ordernameIsNSEC3=false ) override;
        bool createSlaveDomain( const string& ip, const DNSName& domain, const string &nameserver, const string& account ) override;
        bool superMasterBackend( const string& ip, const DNSName& domain, const vector<DNSResourceRecord>& nsset, string *nameserver, string* account, DNSBackend** ddb ) override;

        void getUpdatedMasters( vector<DomainInfo>* updated ) override;
        void getUnfreshSlaveInfos( vector<DomainInfo>* unfresh ) override;

        void setFresh( uint32_t domain_id ) override;
        void setNotified( uint32_t domain_id, uint32_t serial ) override;
};



class OdbxFactory : public BackendFactory
{

public:

        OdbxFactory() : BackendFactory( "opendbx" ) {}


        void declareArguments( const string &suffix="" )
        {
        	declare( suffix, "backend", "OpenDBX backend","mysql" );
        	declare( suffix, "host-read", "Name or address of one or more DBMS server to read from","127.0.0.1" );
        	declare( suffix, "host-write", "Name or address of one or more DBMS server used for updates","127.0.0.1" );
        	declare( suffix, "port", "Port the DBMS server are listening to","" );
        	declare( suffix, "database", "Database name containing the DNS records","powerdns" );
        	declare( suffix, "username","User for connecting to the DBMS","powerdns");
        	declare( suffix, "password","Password for connecting to the DBMS","");

        	declare( suffix, "sql-list", "AXFR query", "SELECT r.\"domain_id\", r.\"name\", r.\"type\", r.\"ttl\", r.\"prio\", r.\"content\" FROM \"records\" r WHERE r.\"domain_id\"=:id" );

        	declare( suffix, "sql-lookup", "Lookup query","SELECT r.\"domain_id\", r.\"name\", r.\"type\", r.\"ttl\", r.\"prio\", r.\"content\" FROM \"records\" r WHERE r.\"name\"=':name'" );
        	declare( suffix, "sql-lookupid", "Lookup query with id","SELECT r.\"domain_id\", r.\"name\", r.\"type\", r.\"ttl\", r.\"prio\", r.\"content\" FROM \"records\" r WHERE r.\"domain_id\"=:id AND r.\"name\"=':name'" );
        	declare( suffix, "sql-lookuptype", "Lookup query with type","SELECT r.\"domain_id\", r.\"name\", r.\"type\", r.\"ttl\", r.\"prio\", r.\"content\" FROM \"records\" r WHERE r.\"name\"=':name' AND r.\"type\"=':type'" );
        	declare( suffix, "sql-lookuptypeid", "Lookup query with type and id","SELECT r.\"domain_id\", r.\"name\", r.\"type\", r.\"ttl\", r.\"prio\", r.\"content\" FROM \"records\" r WHERE r.\"domain_id\"=:id AND r.\"name\"=':name' AND r.\"type\"=':type'" );
        	declare( suffix, "sql-lookupsoa","Lookup query for SOA record","SELECT d.\"id\", d.\"auto_serial\", r.\"ttl\", r.\"content\" FROM \"records\" r JOIN \"domains\" d ON r.\"domain_id\"=d.\"id\" WHERE r.\"name\"=':name' AND r.\"type\"='SOA' AND d.\"status\"='A'" );

        	declare( suffix, "sql-zonedelete","Delete all records for this zone","DELETE FROM \"records\" WHERE \"domain_id\"=:id" );
        	declare( suffix, "sql-zoneinfo","Get domain info","SELECT d.\"id\", d.\"name\", d.\"type\", d.\"master\", d.\"last_check\", d.\"auto_serial\", r.\"content\" FROM \"domains\" d LEFT JOIN \"records\" r ON ( d.\"id\"=r.\"domain_id\" AND r.\"type\"='SOA' ) WHERE d.\"name\"=':name' AND d.\"status\"='A'" );

        	declare( suffix, "sql-transactbegin", "Start transaction", "BEGIN" );
        	declare( suffix, "sql-transactend", "Finish transaction", "COMMIT" );
        	declare( suffix, "sql-transactabort", "Abort transaction", "ROLLBACK" );

        	declare( suffix, "sql-insert-slave","Add slave domain", "INSERT INTO \"domains\" ( \"name\", \"type\", \"master\", \"account\" ) VALUES ( '%s', 'SLAVE', '%s', '%s' )" );
        	declare( suffix, "sql-insert-record","Feed record into table", "INSERT INTO \"records\" ( \"domain_id\", \"name\", \"type\", \"ttl\", \"prio\", \"content\" ) VALUES ( %d, '%s', '%s', %d, %d, '%s' )" );

        	declare( suffix, "sql-update-serial", "Set zone to notified", "UPDATE \"domains\" SET \"notified_serial\"=%d WHERE \"id\"=%d" );
        	declare( suffix, "sql-update-lastcheck", "Set time of last check", "UPDATE \"domains\" SET \"last_check\"=%d WHERE \"id\"=%d" );

        	declare( suffix, "sql-master", "Get master record for zone", "SELECT d.\"master\" FROM \"domains\" d WHERE d.\"name\"=':name' AND d.\"status\"='A' AND d.\"type\"='SLAVE'" );
        	declare( suffix, "sql-supermaster","Get supermaster info", "SELECT s.\"account\" FROM \"supermasters\" s WHERE s.\"ip\"=':ip' AND s.\"nameserver\"=':ns'" );

        	declare( suffix, "sql-infoslaves", "Get all unfresh slaves", "SELECT d.\"id\", d.\"name\", d.\"master\", d.\"last_check\", d.\"notified_serial\", d.\"auto_serial\", r.\"content\" FROM \"domains\" d LEFT JOIN \"records\" r ON ( d.\"id\"=r.\"domain_id\" AND r.\"type\"='SOA' ) WHERE d.\"status\"='A' AND d.\"type\"='SLAVE'" );
        	declare( suffix, "sql-infomasters", "Get all updated masters", "SELECT d.\"id\", d.\"name\", d.\"master\", d.\"last_check\", d.\"notified_serial\", d.\"auto_serial\", r.\"content\" FROM \"domains\" d LEFT JOIN \"records\" r ON ( d.\"id\"=r.\"domain_id\" AND r.\"type\"='SOA' ) WHERE d.\"status\"='A' AND d.\"type\"='MASTER'" );

        	declare( suffix, "host", "deprecated, use host-read and host-write instead","" );
        }


        DNSBackend* make( const string &suffix="" )
        {
        	return new OdbxBackend( suffix );
        }
};


class OdbxLoader
{
        OdbxFactory factory;

public:

        OdbxLoader()
        {
        	BackendMakers().report( &factory );
        	g_log<< Logger::Info << "[opendbxbackend] This is the opendbx backend version " VERSION
#ifndef REPRODUCIBLE
        		<< " (" __DATE__ " " __TIME__ ")"
#endif
        		<< " reporting" << endl;
        }
};


static OdbxLoader odbxloader;



#endif /* ODBXBACKEND_HH */
