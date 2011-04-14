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

/* FIRST PART */

MONGODBBackend::MONGODBBackend(const string &suffix) {
    setArgPrefix("mongodb"+suffix);
    string host;
    try {
    
	if (pthread_equal(backend_pid, pthread_self())) {
    	    backend_count++;
	} else {
    	    backend_count = 1;
    	    backend_pid = pthread_self();
	}
	
        reload();
    
        host = getArg("host");
        mongo::HostAndPort hap = mongo::HostAndPort(host);
        string errmsg;

        if (! m_db.connect(hap, errmsg) ) {
		throw MONGODBException ("Can't connect to '" + host + "' (" + errmsg + ")");
	}
	    
	mongo_db = getArg("database");
	collection_domains = mongo_db + "." + getArg("collection-domains");
	collection_records = mongo_db + "." + getArg("collection-records");

        collection_domainmetadata = mongo_db + "." + getArg("collection-domainmetadata");
	collection_cryptokeys = mongo_db + "." + getArg("collection-cryptokeys");
        collection_tsigkeys = mongo_db + "." + getArg("collection-tsigkeys");

	string mongo_user = getArg("user");
	    
	if (! mongo_user.empty()) {
	    string mongo_password = getArg("password");
		
	    if (! m_db.auth(mongo_db, mongo_user, mongo_password, errmsg)) {
	        throw MONGODBException ("Can't be authorized to database '" +mongo_db + "' with username '" + mongo_user +"' password 'not shown' (" + errmsg + ")");
	    }
	}
	
	if (checkindex) {
	    L<<Logger::Error << backend_name << "(Re)creating index... " << endl;

	    m_db.ensureIndex(collection_domains , BSON( "domain_id" << 1), true, "domain_id", true); //, true);
	    m_db.ensureIndex(collection_domains , BSON( "name" << 1), true, "name", true); //, true);
	    m_db.ensureIndex(collection_domains , BSON( "type" << 1), false, "type", true); //, true);
	    m_db.ensureIndex(collection_domains , BSON( "account" << 1), false, "type", true); //, true);

	    m_db.ensureIndex(collection_records, BSON( "domain_id" << 1), false, "domain_id", true); //, true);
	    m_db.ensureIndex(collection_records, BSON( "name" << 1), false, "name", true); //, true);
	    m_db.ensureIndex(collection_records, BSON( "name" << 1 << "type" << 1), true, "name_type", true); //, true);
	    m_db.ensureIndex(collection_records, BSON( "domain_id" << 1 << "auth" << 1 << "ordername" << -1), false, "domainid_auth_ordername_desc", true); //, true);
	    m_db.ensureIndex(collection_records, BSON( "domain_id" << 1 << "auth" << 1 << "ordername" << 1), false, "domainid_auth_ordername_asc", true); //, true);
	    m_db.ensureIndex(collection_records, BSON( "domain_id" << 1 << "name" << 1 ), false, "domainid_name", true); //, true);

	    m_db.ensureIndex(collection_domainmetadata, BSON( "name" << 1 ), true, "name", true); //, true);
	    m_db.ensureIndex(collection_domainmetadata, BSON( "name" << 1 << "content.kind" << 1), true, "name_kind", true); //, true);

	    m_db.ensureIndex(collection_cryptokeys, BSON( "domain_id" << 1 ), true, "domain_id", true); //, true);
    	    m_db.ensureIndex(collection_cryptokeys, BSON( "name" << 1 ), true, "name", true); //, true);
    	    m_db.ensureIndex(collection_cryptokeys, BSON( "name" << 1 << "domain_id" << 1), true, "name_domainid", true); //, true);
    	    m_db.ensureIndex(collection_cryptokeys, BSON( "domain_id" << 1 << "content.id" << 1), true, "domainid_id", true); //, true);
    	    m_db.ensureIndex(collection_cryptokeys, BSON( "name" << 1 << "content.id" << 1), true, "name_id", true); //, true);

	    m_db.ensureIndex(collection_tsigkeys, BSON( "name" << 1 << "content.algorithm" << 1), true, "name_algo", true); //, true);

	}
    }
	
    catch(MONGODBException &e) {
        L<<Logger::Error<<backend_name<<"Error: "<<e.what<<endl;
        throw AhuException(e.what);
    }
    
    L<<Logger::Info << backend_name << "Connected to host: " << host << " with database: " << mongo_db << endl;
    
}
  
MONGODBBackend::~MONGODBBackend() {
//	delete m_db;
    L<<Logger::Info<<backend_name<<"Disconnected!" << endl;
}

bool MONGODBBackend::list(const string &target, int domain_id) {
    
    mongo_query = QUERY( "domain_id" << domain_id );
	
    elements = false;
    default_ttl = 0;
	
    if(logging)
	L<<Logger::Info<< backend_name << "(list) Query: "<< mongo_query.toString() << endl;

    cursor = m_db.query(collection_records, mongo_query );

    return cursor->more();
}
    
void MONGODBBackend::lookup(const QType &qtype, const string &qname, DNSPacket *p, int domain_id) {
    string q_type;

    q_type = qtype.getName();
    q_name = qname;
    
    mongo_query = q_type == "ANY" ? QUERY( "name" << toLower(qname) ) : QUERY( "name" << toLower(qname) << "type" << q_type);
	
    elements = false;
    default_ttl = 0;

    if(logging)
	L<<Logger::Info<< backend_name <<"(lookup) Query: "<< mongo_query.toString() << endl;
	
    cursor = m_db.query(collection_records, mongo_query);
	
}

bool MONGODBBackend::content(DNSResourceRecord* rr) {
    
again:
    if (!contents->more()) 
	return false;
	    
    bson::bo o1, o2;
	    
    o1 = contents->next().wrap();
	    
    if(logging_content)
	L<<Logger::Info<< backend_name <<"(content) Contents: " << o1.toString() << endl;
	    
    rr->qname.clear();
    rr->qtype = 255;
    rr->ttl = 0;
    rr->domain_id = 0;
    rr->last_modified = 0;
    rr->priority = 0;
    rr->content.clear();
    rr->auth = false;
	
    o2 = o1.firstElement().embeddedObject();

    if (!o2.hasElement("data")) {
        L<<Logger::Error<< backend_name << "(content) Error: The record '" << o2.toString() << "' is missing 'data' for the query '"<< mongo_query.toString() << "'" << endl;
        goto again;
    }

    if ((type == "MX" || type == "SRV") && !o2.hasElement("prio")) {
        L<<Logger::Error<< backend_name << "(content) Error: The record '" << o2.toString() << "' is missing 'prio' for the query '"<< mongo_query.toString() << "'" << endl;
        goto again;
    }

    rr->qtype = rr_record.qtype;
    rr->qname = rr_record.qname;
    rr->domain_id = rr_record.domain_id;
    rr->last_modified = rr_record.last_modified;
    rr->auth = rr_record.auth;

    rr->priority = o2.getIntField("prio");

    if (o2.hasElement("ttl"))
	rr->ttl = o2.getIntField("ttl");
    else 
	rr->ttl = rr_record.ttl;
	    
    rr->content = o2.getStringField("data");
    if (rr->content.empty()) {
	L<<Logger::Error<< backend_name << "(content) Error: The record '" << o2.toString() << "' has no content for the query '"<< mongo_query.toString() << "'" << endl;
	goto again;
    }

    return contents->more();
}

bool MONGODBBackend::get(DNSResourceRecord &rr) {

    rr.content.clear();
	    
    if (elements) {
        elements = content(&rr);
        if (!rr.content.empty() ) 
	    return true;
    } 

again:	
    if (cursor->more()) {
		
    mongo_record = cursor->next();
		
    if(logging_content)
	L<<Logger::Info<< backend_name << "(get) mongo_record " << mongo_record.toString() << endl;
		
	if (mongo_record.hasElement("type") && mongo_record.hasElement("domain_id") && mongo_record.hasElement("name") && mongo_record.hasElement("content")) {
    	    type = mongo_record.getStringField("type");
		    
    	    rr_record.qtype = type;
	    rr_record.qname = mongo_record.getStringField("name");
    	    rr_record.domain_id = mongo_record.getIntField("domain_id");
	    rr_record.auth = mongo_record.getIntField("auth");
            rr_record.last_modified = 0;
	    rr_record.priority = 0;
    	    rr_record.content.clear();

            rr_record.ttl = mongo_record.getIntField("ttl");
	    if (rr_record.ttl == 0) {
    	        rr_record.ttl = ::arg().asNum( "default-ttl" );
    		if (rr_record.ttl == 0 && default_ttl == 0) {
    		    SOAData soadata;
		    DomainInfo DI;
    		
    		    if (getDomainInfo("", DI, &soadata, rr_record.domain_id)) {
    			if (!use_default_ttl && (soadata.ttl < soadata.default_ttl)) 
    			    default_ttl = soadata.ttl;
    			else 
    			    default_ttl = soadata.default_ttl;
    			
    			rr_record.ttl = default_ttl;
    		    
			if(logging)
			    L<<Logger::Info<< backend_name << "(get) Got default_ttl: '" << default_ttl << "' from SOA for recordname '" << rr_record.qname << "'" << endl;
    		    } else {
			L<<Logger::Error << backend_name << "(get) Could not get SOA for default_ttl for recordname '" << rr_record.qname << "'!" << endl;
			goto again;
    		    }
    		} else if (rr_record.ttl == 0 && default_ttl > 0) {
    		    rr_record.ttl = default_ttl;
    		} else {
		    L<<Logger::Error << backend_name << "(get) Could not get default_ttl for recordname '" << rr_record.qname << "'!" << endl;
		    goto again;
		}
	    }
	
//		if (contents)
//			delete contents;

	    contents = new mongo::BSONObjIterator(mongo_record.getObjectField("content"));
		    
	    elements = content(&rr);
		
	} else {
	    L<<Logger::Error<< backend_name << "(get) Error: The record '" << mongo_record.toString() << "' is missing required element(s) for the query '"<< mongo_query.toString() << "'" << endl;
	    goto again;
	}
    } 
	
    return !rr.content.empty() ;
}

bool MONGODBBackend::getSOA(const string &name, SOAData &soadata, DNSPacket *p) {
    //please see getDomainInfo in slave.cc for this function.
    
    DomainInfo DI;

    return getDomainInfo(name, DI, &soadata);
}
