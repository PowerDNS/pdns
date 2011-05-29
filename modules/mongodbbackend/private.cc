/*
    Copyright (C) 2011 Fredrik Danerklint

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as published 
    by the Free Software Foundation

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

#include "mongodbbackend.hh"

#include "pdns/logger.hh"
#include "pdns/arguments.hh"

bool MONGODBBackend::checkDomainInfo(const string *domain, mongo::BSONObj *mongo_r, string *f_name, string *mongo_q, DomainInfo *di, SOAData *soadata) {
    if (mongo_r->hasElement("type") && mongo_r->hasElement("domain_id") && mongo_r->hasElement("SOA")) {
	di->backend = this;
	di->serial = 0;
	di->zone = *domain;
	    
	di->id = mongo_r->getIntField("domain_id");
	di->last_check = mongo_r->getIntField("last_check");
	di->notified_serial = mongo_r->getIntField("notified_serial");

	if (soadata == NULL) 
	    for( bson::bo::iterator i(mongo_r->getObjectField("masters")); i.more(); ) {
    		bson::bo o;
        	bson::be e;
        	o = i.next().wrap();
        	e = o.firstElement();
        	di->masters.push_back(e.valuestr());
    	    }

	string type = toUpper(mongo_r->getStringField("type"));
	
	if (soadata != NULL || type == "SLAVE") {
	    //filling out soadata. 
	    mongo::BSONObj soa = mongo_r->getObjectField("SOA");
	    if (soa.hasElement("serial") && soa.hasElement("refresh") && soa.hasElement("retry") && soa.hasElement("expire") && soa.hasElement("default_ttl") && mongo_r->hasElement("ttl")) {
		if (soadata != NULL) {
		    soadata->db = this;
		    soadata->serial = soa.getIntField("serial");
		    di->serial = soadata->serial;
		
		    soadata->refresh = soa.getIntField("refresh");
		    soadata->retry = soa.getIntField("retry");
		    soadata->expire = soa.getIntField("expire");
		    soadata->default_ttl = soa.getIntField("default_ttl");
		    soadata->domain_id = di->id;
		    
		    soadata->ttl = mongo_r->getIntField("ttl");
		    
		    soadata->nameserver = soa.getStringField("nameserver");
		    if (soadata->nameserver.empty()) {
			soadata->nameserver = arg()["default-soa-name"];
			if (soadata->nameserver.empty()) {
    			    L<<Logger::Error << backend_name << *f_name << " Error: SOA Record '" << soa.toString() << "' is missing nameserver for the query '" << *mongo_q << "'" << endl; 
    			    return false;
			}
		    }
		    soadata->hostmaster = soa.getStringField("hostmaster");
		    if (soadata->hostmaster.empty()) 
			soadata->hostmaster = "hostmaster." + *domain;
			
		} else {
		    //hopefully called as getDomainInfo with no soadata!
		    di->serial = soa.getIntField("serial");
		}
		
	    } else {
    		L<<Logger::Error << backend_name << *f_name << " Error: SOA Record '" << soa.toString() << "' is missing required element(s) for the query '" << *mongo_q << "'" << endl; 
		return false;
	    }
	}
	    
	if (type == "SLAVE") {
	    di->kind = DomainInfo::Slave;
	    
	} else if (type == "MASTER") {
	    di->kind = DomainInfo::Master;
	    
	} else {
	    di->kind = DomainInfo::Native;
	}
	    
	return true;
	    
    } else {
        L<<Logger::Error << backend_name << *f_name << " Error: The record '" << mongo_r->toString() << "' is missing required element(s) for the query '" << *mongo_q << "'" << endl; 
    }
    
    return false;
}

void MONGODBBackend::getTheFreshOnes(vector<DomainInfo>* domains, string *type, string *f_name) {
    mongo::Query mongo_q = QUERY( "type" << *type );

    auto_ptr<mongo::DBClientCursor> mongo_c;
    mongo_c = m_db.query(collection_domains, mongo_q);

    string m_q = mongo_q.toString();
    
    if(logging)
        L<<Logger::Info << backend_name << *f_name << " Query: "<< m_q << endl;

    if (!mongo_c->more()) 
	return;
    
    while(mongo_c->more()) {
	DomainInfo di;
	SOAData sd;
	
	mongo::BSONObj mongo_r = mongo_c->next();
	
	string domain = mongo_r.getStringField("domain");
	
	if (checkDomainInfo(&domain, &mongo_r, f_name, &m_q, &di, &sd)) {
	    if ( (*type == "SLAVE" && ((time_t)(di.last_check + sd.refresh) < time(0)) ) || (*type == "MASTER" && (di.notified_serial != sd.serial) ) ) {
		di.serial = sd.serial;
		domains->push_back(di);
	    }
	}
    }
}
