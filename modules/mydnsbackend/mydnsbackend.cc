/*
 * PowerDNS backend module for MyDNS style databases
 * Author: Jonathan Oddy (Hostway UK) <jonathan@woaf.net>
 *
 * The schema used by MyDNS isn't suitable for retrieving results with a single
 * query. This means that existing PowerDNS backends are unable to make use of
 * the schema without lame hackery (or awful performance.) This module does
 * the nasty lookup logic required to make use of the schema, and should be as
 * tolerant as MyDNS when it comes to things being fully qualified or not.
 *
 * A known "bug" is that AXFRs will fail if your rr table contains invalid
 * junk. I'm not sure this is really a bug, if you've decided to put free-form
 * text in your data for an A record you have bigger issues.
 *
 * I'd advise avoiding the MyDNS schema if at all possible as the query count
 * for even simple lookups is daft. It's quite trivial to craft a request
 * that'll require 128 database queries to answer with a servfail!
 *
 * If you do not know what mydns is: http://mydns.bboy.net/
 */

#include <string>
#include <map>
#include <unistd.h>
#include <stdlib.h>
#include <sstream>

#include "pdns/namespaces.hh"

#include <pdns/dns.hh>
#include <pdns/dnsbackend.hh>
#include "mydnsbackend.hh"
#include <pdns/dnspacket.hh>
#include <pdns/ueberbackend.hh>
#include <pdns/pdnsexception.hh>
#include <pdns/logger.hh>
#include <pdns/arguments.hh>

#include <modules/gmysqlbackend/smysql.hh>

static string backendName="[MyDNSbackend]";

MyDNSBackend::MyDNSBackend(const string &suffix) {
        setArgPrefix("mydns"+suffix);

        try {
        	d_db = new SMySQL(getArg("dbname"),
        			getArg("host"),
        			getArgAsNum("port"),
        			getArg("socket"),
        			getArg("user"),
        			getArg("password"));

        }
        catch(SSqlException &e) {
        	L<<Logger::Error<<backendName<<" Connection failed: "<<e.txtReason()<<endl;
        	throw PDNSException(backendName+"Unable to launch connection: "+e.txtReason());
        }

        d_rrtable=getArg("rr-table");
        d_soatable=getArg("soa-table");
        d_rrwhere=(mustDo("rr-active")?"active = 1 and ":"")+getArg("rr-where");
        d_soawhere=(mustDo("soa-active")?"active = 1 and ":"")+getArg("soa-where");
        d_useminimalttl=mustDo("use-minimal-ttl");
        d_minimum=0;

        L<<Logger::Warning<<backendName<<" Connection successful"<<endl;
}

MyDNSBackend::~MyDNSBackend() {
        if (d_db)
                delete(d_db);
}


void MyDNSBackend::Query(const string &query) {
        try {
        	d_db->doQuery(query);
        } catch (SSqlException &e) {
        	throw PDNSException("Query failed: "+e.txtReason());
        }
}

bool MyDNSBackend::list(const string &target, int zoneId, bool include_disabled) {
        string query;
        string sname;
        SSql::row_t rrow;

        d_db->setLog(::arg().mustDo("query-logging"));

        query = "select origin, minimum from "+d_soatable+" where id = ";
        query+=itoa(zoneId);
        if (!d_soawhere.empty())
                query+= " and "+d_soawhere;

        this->Query(query);

        if(!d_db->getRow(rrow))
        	return false; // No such zone
        
        d_origin = rrow[0];
        if (d_origin[d_origin.length()-1] == '.')
        	d_origin.erase(d_origin.length()-1);
        d_minimum = atol(rrow[1].c_str());

        while (d_db->getRow(rrow)) {
        	L<<Logger::Warning<<backendName<<" Found more than one matching origin for zone ID: "<<zoneId<<endl;
        };

        query = "select type, data, aux, ttl, zone, name from "+d_rrtable+" where zone = ";
        query+=itoa(zoneId);
        if (!d_rrwhere.empty())
                query += " and "+d_rrwhere;
        

        this->Query(query);

        d_qname = "";
        return true;

}

bool MyDNSBackend::getSOA(const string& name, SOAData& soadata, DNSPacket*) {
        string query;
        SSql::row_t rrow;

        d_db->setLog(::arg().mustDo("query-logging"));

        if (name.empty())
        	return false;

        query = "select id, mbox, serial, ns, refresh, retry, expire, minimum, ttl from "+d_soatable+" where origin = '";

        if (name.find_first_of("'\\")!=string::npos)
        	query+=d_db->escape(name);
        else
        	query+=name;

        query+=".'";
        if (! d_soawhere.empty())
                query += " and "+d_soawhere;

        this->Query(query);

        if(!(d_db->getRow(rrow))) {
        	return false;
        }

        soadata.qname = name;
        soadata.domain_id = atol(rrow[0].c_str());
        soadata.hostmaster = rrow[1];
        soadata.serial = atol(rrow[2].c_str());
        soadata.nameserver = rrow[3];
        soadata.refresh = atol(rrow[4].c_str());
        soadata.retry = atol(rrow[5].c_str());
        soadata.expire = atol(rrow[6].c_str());
        soadata.default_ttl = atol(rrow[7].c_str());
        soadata.ttl = atol(rrow[8].c_str());
        if (d_useminimalttl && soadata.ttl < soadata.default_ttl) {
        	soadata.ttl = soadata.default_ttl;
        }
        soadata.db = this;

        while (d_db->getRow(rrow)) {
        	L<<Logger::Warning<<backendName<<" Found more than one matching zone for: "+name<<endl;
        };

        return true;
}

void MyDNSBackend::lookup(const QType &qtype, const string &qname, DNSPacket *p, int zoneId) {
        string query;
        string sname;
        string zoneIdStr = itoa(zoneId);
        SSql::row_t rrow;
        bool found = false;

        d_origin = "";

        d_db->setLog(::arg().mustDo("query-logging"));

        if (qname.empty())
        	return;

        // Escape the name, after this point we only want to use it in queries
        if (qname.find_first_of("'\\")!=string::npos)
        	sname=d_db->escape(qname);
        else
        	sname = qname;
        sname += ".";

        if (zoneId < 0) {
        	// First off we need to work out what zone we're working with
        	// MyDNS records aren't always fully qualified, so we need to work out the zone ID.
        	
        	size_t pos;
        	string sdom;

        	pos = 0;
        	sdom = sname;
        	while (!sdom.empty() && pos != string::npos) {
        		query = "select id, origin, minimum from "+d_soatable+" where origin = '"+sdom+"'";
                        if (!d_soawhere.empty()) 
                                query += " and "+d_soawhere;

        		this->Query(query);
        		if(d_db->getRow(rrow)) {
                                zoneIdStr=rrow[0];
        			d_origin = rrow[1];
        			if (d_origin[d_origin.length()-1] == '.')
        				d_origin.erase(d_origin.length()-1);
        			d_minimum = atol(rrow[2].c_str());
        			found = true;
        			break;
        		}

        		pos = sname.find_first_of(".",pos+1);
        		sdom = sname.substr(pos+1);
        	}

        } else {
        	query = "select origin, minimum from "+d_soatable+" where id = ";
        	query+=zoneIdStr;
                if (!d_soawhere.empty()) 
        	       query+= " and "+d_soawhere;

        	this->Query(query);

        	if(!d_db->getRow(rrow)) {
        		throw PDNSException("lookup() passed zoneId = "+zoneIdStr+" but no such zone!");
        	}
        	
        	found = true;
        	d_origin = rrow[0];
        	if (d_origin[d_origin.length()-1] == '.')
        		d_origin.erase(d_origin.length()-1);
        	d_minimum = atol(rrow[1].c_str());
        }


        if (found) {

        	while (d_db->getRow(rrow)) {
        		L<<Logger::Warning<<backendName<<" Found more than one matching zone for: "+d_origin<<endl;
        	};
        	// We found the zoneId, so we can work out how to find our rr
        	string host;

        	// The host part of the query is the name less the origin
        	if (qname.length() == d_origin.length())
        		host = "";
        	else
        		host = qname.substr(0, (qname.length() - d_origin.length())-1);

        	if (host.find_first_of("'\\")!=string::npos)
        		host=d_db->escape(host);

        	query = "select type, data, aux, ttl, zone from "+d_rrtable+" where zone = ";
        	query+= zoneIdStr;
        	query += " and (name = '"+host+"' or name = '"+sname+"')";

        	if(qtype.getCode()!=255) {  // ANY
        		query+=" and type='";
        		query+=qtype.getName();
        		query+="'";

        	}
                if (!d_rrwhere.empty())
                        query += " and "+d_rrwhere;


                if (qtype.getCode() == 255) {
                        query += " union select 'SOA' as type, origin as data, '0' as aux, ttl, id as zone from "+d_soatable+" where id= " + zoneIdStr + " and origin = '"+qname+".'";
                        if (!d_soawhere.empty()) 
                                query += " and " + d_soawhere;
                }
        	query += " order by type,aux,data";

        	this->Query(query);

        	d_qname = qname;
        }

}

bool MyDNSBackend::get(DNSResourceRecord &rr) {
        if (d_origin.empty()) {
        	// This happens if lookup() couldn't find the zone
        	return false;
        }

        SSql::row_t rrow;

        if(!d_db->getRow(rrow)) {
        	return false;
        }

        rr.qtype=rrow[0];
        rr.content = rrow[1];

        if(!d_qname.empty()) {
        	// use this to distinguish between select with 'name' field (list()) and one without
        	rr.qname=d_qname;
        } else {
        	rr.qname=rrow[5];
        	if (rr.qname[rr.qname.length()-1] == '.') {
        		rr.qname.erase(rr.qname.length()-1); // Fully qualified, nuke the last .
        	} else {
        		if (!rr.qname.empty())
        			rr.qname += ".";
        		rr.qname += d_origin; // Not fully qualified
        	}

        }

        if (rr.qtype.getCode() == QType::NS || rr.qtype.getCode()==QType::MX || 
                rr.qtype.getCode() == QType::CNAME || rr.qtype.getCode() == QType::PTR) {
        	if (rr.content[rr.content.length()-1] == '.') {
        		rr.content.erase(rr.content.length()-1); // Fully qualified, nuke the last .
        	} else {
        		if (!rr.content.empty())
        			rr.content += ".";
        		rr.content += d_origin;
        	}
        }

        rr.priority = atol(rrow[2].c_str());
        rr.ttl = atol(rrow[3].c_str());
        if (d_useminimalttl && rr.ttl < d_minimum)
        	rr.ttl = d_minimum;
        rr.domain_id=atol(rrow[4].c_str());

  
        rr.last_modified=0;

        return true;

}

class MyDNSFactory : public BackendFactory {

public:
        MyDNSFactory() : BackendFactory("mydns") {}

        void declareArguments(const string &suffix = "") {
        	declare(suffix,"dbname","Pdns backend database name to connect to","mydns");
        	declare(suffix,"user","Pdns backend user to connect as","powerdns");
        	declare(suffix,"host","Pdns backend host to connect to","");
        	declare(suffix,"port","Pdns backend host to connect to","");
        	declare(suffix,"password","Pdns backend password to connect with","");
        	declare(suffix,"socket","Pdns backend socket to connect to","");
        	declare(suffix,"rr-table","Name of RR table to use","rr");
        	declare(suffix,"soa-table","Name of SOA table to use","soa");
        	declare(suffix,"soa-where","Additional WHERE clause for SOA","1 = 1");
        	declare(suffix,"rr-where","Additional WHERE clause for RR","1 = 1");
        	declare(suffix,"soa-active","Use the active column in the SOA table","yes");
        	declare(suffix,"rr-active","Use the active column in the RR table","yes");
        	declare(suffix,"use-minimal-ttl","Setting this to 'yes' will make the backend behave like MyDNS on the TTL values. Setting it to 'no' will make it ignore the minimal-ttl of the zone.","yes");
        }

        MyDNSBackend *make(const string &suffix = "") {
        	return new MyDNSBackend(suffix);
        }

};

class MyDNSLoader {

public:
        MyDNSLoader() {
        	BackendMakers().report(new MyDNSFactory());
		L << Logger::Info << "[mydnsbackend] This is the mydns backend version " VERSION " reporting" << endl;
        }
};

static MyDNSLoader mydnsloader;
