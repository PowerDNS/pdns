/* 
 * File:   libgeosqlbackend.h
 * Author: Shin Sterneck ( email: shin at sterneck dot asia )
 *
 * Created on July 28, 2013, 11:56 AM
 */

#ifndef GEOSQLBACKEND_H
#define	GEOSQLBACKEND_H

#define LOGID                   "[GeoSqlBackend]"
#define BACKEND_VERSION         "1.4.2"

#include <opendbx/api>
#include "pdns/utility.hh"
#include "pdns/dnsbackend.hh"
#include "pdns/dns.hh"
#include "pdns/dnsbackend.hh"
#include "pdns/dnspacket.hh"
#include "pdns/ahuexception.hh"
#include "pdns/logger.hh"
#include "boost/regex.hpp"
#include <boost/progress.hpp>

using std::string;

class GeoSqlBackend : public DNSBackend {
public:
    GeoSqlBackend(const string &suffix);    
    virtual ~GeoSqlBackend();

    bool list(const string &target, int id);
    void lookup(const QType &type, const string &qdomain, DNSPacket *p, int zoneId);
    bool get(DNSResourceRecord &rr);
    bool getSOA(const string &name, SOAData &soadata, DNSPacket *p);

private:
    bool getDnsidForIP(string &ip, string &returned_countryID);
    bool getGeoDnsRecords(const QType &type, const string &qdomain, string &dnsid);
    bool getSqlData(OpenDBX::Conn *&conn, string &sqlStatement, std::vector< std::vector<string> > &sqlResponseData );
    void logEntry(string message);
    
    string regex_filter;
    string domain_suffix;
    
    OpenDBX::Conn *geoip_db, *pdns_db;
    vector<DNSResourceRecord> *rrs;     
};

#endif	/* GEOSQLBACKEND_H */