/* 
 * File:   GeoSqlBackend.cpp
 * Author: Shin Sterneck ( email: shin at sterneck dot asia )
 * 
 * Created on July 28, 2013, 11:56 AM
 */

#include "geosqlbackend.h"

// constructor

GeoSqlBackend::GeoSqlBackend(const string &suffix) {
    logEntry("Loading GeoSQLBackend Version " + string(BACKEND_VERSION));

    // load configuration
    setArgPrefix("geosql" + suffix);
    regex_filter = getArg("regex_filter");
    domain_suffix = getArg("domain_suffix");
    string geo_backend = "mysql";
    string geo_host = getArg("geo_host");
    string geo_username = getArg("geo_username");
    string geo_password = getArg("geo_password");
    string geo_database = getArg("geo_database");
    string pdns_backend = "mysql";
    string pdns_host = getArg("pdns_host");
    string pdns_database = getArg("pdns_database");
    string pdns_username = getArg("pdns_username");
    string pdns_password = getArg("pdns_password");

    rrs = new vector<DNSResourceRecord>();

    try {
        logEntry("Trying to connect GeoIP Database");
        geoip_db = new OpenDBX::Conn(geo_backend, geo_host, "");
        geoip_db->bind(geo_database, geo_username, geo_password, ODBX_BIND_SIMPLE);
        logEntry("Bound to GeoIP Database");

        logEntry("Trying to connect PowerDNS Database");
        
        if (boost::iequals(geo_host,pdns_host) && boost::iequals(geo_username,pdns_username) && boost::iequals(geo_password,pdns_password)) {
            pdns_db = geoip_db;
        } else {
            pdns_db = new OpenDBX::Conn(pdns_backend, pdns_host, "");
            pdns_db->bind(pdns_database, pdns_username, pdns_password, ODBX_BIND_SIMPLE);
        }
        
        logEntry("Bound to PowerDNS Database");
    } catch (OpenDBX::Exception &e) {
        logEntry("Connection to database server could not be established! ODBX Error code: " + e.getCode());
        exit(1);
    }
}

// destructor

GeoSqlBackend::~GeoSqlBackend() {
    geoip_db->unbind();
    geoip_db->finish();
    pdns_db->unbind();
    pdns_db->finish();
    delete geoip_db;
    delete pdns_db;
    delete rrs;
}

// no support for zone transfers in this backend.

bool GeoSqlBackend::list(const string &target, int id) {
    return false;
}

/* Method for looking up the DNS records and storing the result into a vector.
 * This method is called by PowerDNS
 */

void GeoSqlBackend::lookup(const QType &type, const string &qdomain, DNSPacket *p, int zoneId) {
    if (boost::regex_match(qdomain, boost::regex(regex_filter))) {
        zoneId = 1;
        logEntry("Handling Query Request: '" + string(qdomain) + ":" + string(type.getName()) + "'");

        string dnsid;
        string remote_ip = p->getRemote();
        getDnsidForIP(remote_ip, dnsid);
        logEntry("Identified GeoIP ID as: '" + dnsid + "'");

        getGeoDnsRecords(type, qdomain, dnsid);

    } else {
        logEntry("Skipping Query request: '" + qdomain + "' not matching regex_filter.");
    }
}

// Method used by PowerDNS to retrieve our prepared DNS records.

bool GeoSqlBackend::get(DNSResourceRecord &rr) {
    if (rrs->size() > 0) {
        rr = rrs->at(rrs->size() - 1);
        rrs->pop_back();
        return true;
    }

    return false;
}

bool GeoSqlBackend::getSOA(const string &name, SOAData &soadata, DNSPacket *p) {
    return false;
}

/*
 * method to get our DNS-ID
 */

bool GeoSqlBackend::getDnsidForIP(string &ip, string &returned_dnsid) {
    bool foundCountry = false;
    string sqlQuery = "select dnsid from maxmind where dnsid <> 'NULL' and inet_aton('" + ip + "') between start and end limit 1;";

    std::vector<std::vector<string> > sqlResponseData;
    if (getSqlData(geoip_db, sqlQuery, sqlResponseData) 
            && (sqlResponseData.size() > 0 && !sqlResponseData[0].at(0).empty())) {
        returned_dnsid = sqlResponseData[0].at(0);
        foundCountry = true;
    }

    if (!foundCountry) returned_dnsid = "default";

    return foundCountry;
}

// retrieve the DNS records depending on the geo location (assigned by dnsid)

bool GeoSqlBackend::getGeoDnsRecords(const QType &type, const string &qdomain, string &dnsid) {
    bool foundRecords = false;

    string sqlWhereTypeClause;
    if (type.getCode() == QType::ANY) {
        sqlWhereTypeClause = "type != 'soa'";
    } else {
        sqlWhereTypeClause = "type='" + type.getName() + "'";
    }

    string sqlQuery = "select replace(name, '." + dnsid + domain_suffix + "',''),type,replace(content, '." + dnsid + domain_suffix + "',''),ttl,prio from records where name like '" + qdomain + "." + dnsid + domain_suffix + "' and " + sqlWhereTypeClause + ";";

    std::vector<std::vector<string> > sqlResponseData;
    if (getSqlData(pdns_db, sqlQuery, sqlResponseData) && sqlResponseData.size() > 0) {
        DNSResourceRecord record;
        record.auth = 1;
        for (int i = 0; i < sqlResponseData.size(); i++) {
            record.qname = sqlResponseData[i].at(0);
            record.qtype = sqlResponseData[i].at(1);
            record.content = sqlResponseData[i].at(2);
            std::istringstream(sqlResponseData[i].at(3)) >> record.ttl;
            std::istringstream(sqlResponseData[i].at(4)) >> record.priority;

            rrs->push_back(record);
        }
        foundRecords = true;
    }

    return foundRecords;
}

//unified way of handling sql queries and storing the result into a multidimensional vector (row/column)

bool GeoSqlBackend::getSqlData(OpenDBX::Conn *&conn, string &sqlStatement, std::vector< std::vector<string> > &sqlResponseData) {
    bool dataAvailable = false;
    sqlResponseData.clear();

    if (!sqlStatement.empty()) {
        try {
            logEntry("Running SQL statement: " + sqlStatement);
            OpenDBX::Result result = conn->create(sqlStatement).execute();

            odbxres stat;
            ostringstream os1;

            while ((stat = result.getResult())) {
                switch (stat) {                    
                    case ODBX_RES_TIMEOUT:
                        logEntry("ODBX_RES_TIMEOUT");
                        throw;
                    case ODBX_RES_NOROWS:
                        logEntry("ODBX_RES_NOROWS");
                        break;
                    case ODBX_RES_DONE:
                        logEntry("ODBX_RES_DONE");
                        break;
                    case ODBX_RES_ROWS:
                        while (result.getRow() != ODBX_ROW_DONE) {
                            std::vector<string> row;
                            for (int i = 0; i < result.columnCount(); i++) {
                                os1 << result.fieldValue(i);
                                row.push_back(os1.str());
                                os1.str("");
                                os1.clear();
                            }
                            sqlResponseData.push_back(row);
                        }
                        if (!sqlResponseData.empty()) dataAvailable = true;
                }
                continue;
            }

        } catch (std::exception &e1) {
            logEntry("Caught exception during SQL Statement: " + string(e1.what()));
        }
    }
    return dataAvailable;
}

// simple method to handle unified way of logging

void GeoSqlBackend::logEntry(string message) {
    L << Logger::Info << LOGID << " " << message << endl;
}

class GeoSqlFactory : public BackendFactory {
public:

    GeoSqlFactory() : BackendFactory("geosql") {
    }

    void declareArguments(const string &suffix) {
        // GeoDB DB Connection part
        declare(suffix, "regex_filter", "Regex filter to match against", ".*");
        declare(suffix, "domain_suffix", "Set the domain suffix for geoip enabled zones", ".geopdns");
        declare(suffix, "geo_host", "The GeoIP Database server IP/FQDN", "localhost");
        declare(suffix, "geo_database", "The GeoIP Database name", "pdns");
        declare(suffix, "geo_username", "The GeoIP Database username", "pdns");
        declare(suffix, "geo_password", "The GeoIP Database password", "pdns");

        // PowerDNS DB Connection part
        declare(suffix, "pdns_host", "The PowerDNS Database server IP/FQDN", "localhost");
        declare(suffix, "pdns_database", "The PowerDNS Database name", "geoip");
        declare(suffix, "pdns_username", "The PowerDNS Database username", "geoip");
        declare(suffix, "pdns_password", "The PowerDNS Database password", "geoip");
    }

    DNSBackend *make(const string &suffix) {
        L << Logger::Info << LOGID << " Making GeoSQL backend." << endl;

        return new GeoSqlBackend(suffix);
    }
};

class GeoSqlLoader {
public:

    GeoSqlLoader() {
        BackendMakers().report(new GeoSqlFactory);
    }

};

static GeoSqlLoader geosqlloader;
