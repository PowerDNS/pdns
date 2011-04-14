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

/* 
    virtual bool updateDNSSECOrderAndAuth(uint32_t domain_id, const std::string& zonename, const std::string& qname, bool auth) 
    virtual bool updateDNSSECOrderAndAuthAbsolute(uint32_t domain_id, const std::string& qname, const std::string& ordername, bool auth) 
    virtual bool getBeforeAndAfterNamesAbsolute(uint32_t id, const std::string& qname, std::string& unhashed, std::string& before, std::string& after)

    virtual bool getDomainKeys(const string& name, unsigned int kind, std::vector<KeyData>& keys)
    virtual bool removeDomainKey(const string& name, unsigned int id)
    virtual int addDomainKey(const string& name, const KeyData& key)
    virtual bool activateDomainKey(const string& name, unsigned int id)
    virtual bool deactivateDomainKey(const string& name, unsigned int id)

    virtual bool getTSIGKey(const string& name, string* algorithm, string* content) { return false; }

    virtual bool setDomainMetadata(const string& name, const std::string& kind, std::vector<std::string>& meta)
    virtual bool getDomainMetadata(const string& name, const std::string& kind, std::vector<std::string>& meta)
    virtual void alsoNotifies(const string &domain, set<string> *ips)

*/

bool MONGODBBackend::updateDNSSECOrderAndAuth(uint32_t domain_id, const std::string& zonename, const std::string& qname, bool auth) {

    if(!dnssec)
	return false;

    string ins=toLower(labelReverse(makeRelative(qname, zonename)));
    return this->updateDNSSECOrderAndAuthAbsolute(domain_id, qname, ins, auth);
}

bool MONGODBBackend::updateDNSSECOrderAndAuthAbsolute(uint32_t domain_id, const std::string& qname, const std::string& ordername, bool auth) {
    if(!dnssec)
	return false;

    mongo::Query mongo_q = QUERY( "name" << qname << "domain_id" << domain_id );
    bson::bo update = BSON( "$set" << BSON("ordername" << ordername << "auth" << auth) );

    if(logging) {
        L<<Logger::Info << backend_name << "(updateDNSSECOrderAndAuthAbsolute) Query: '"<< mongo_q.toString() << "'" << endl;
	if(logging_content) 
    	    L<<Logger::Info << backend_name << "(updateDNSSECOrderAndAuthAbsolute) Update: '"<< update.toString() << "'" << endl;
    }
    
    if(logging_cerr) {
        cerr << backend_name << "(updateDNSSECOrderAndAuthAbsolute) Query: '"<< mongo_q.toString() << "'" << endl;
	if(logging_content) 
    	    cerr << backend_name << "(updateDNSSECOrderAndAuthAbsolute) Update: '"<< update.toString() << "'" << endl;
    }
        
    m_db.update(collection_records, mongo_q , update);

    return true;
}

bool MONGODBBackend::getBeforeAndAfterNamesAbsolute(uint32_t id, const std::string& qname, std::string& unhashed, std::string& before, std::string& after) {
    if(logging)
	L<<Logger::Info  << backend_name << "(getBeforeAndAfterNamesAbsolute) BEGIN domain_id: '" << id << "' qname: '" << qname << "'" << endl;
     
    unhashed.clear(); 
    before.clear(); 
    after.clear();

    string lqname = toLower(qname);

    mongo::Query mongo_q = QUERY( "domain_id" << id << "auth" << true << "ordername" << BSON("$gt" << lqname ) );

    auto_ptr<mongo::DBClientCursor> mongo_c;

    bool afterafter = false;
    bson::bo fields = BSON("ordername" << 1);
    
retryAfter:
    if(logging)
        L<<Logger::Info << backend_name << "(getBeforeAndAfterNamesAbsolute) Query after: '"<< mongo_q.toString() << "'" << endl;

    mongo_q.hint(BSON("domain_id" << 1 << "auth" << 1 << "ordername" << 1));
    mongo::BSONObj mongo_r = m_db.findOne(collection_records, mongo_q, &fields );

    if (mongo_r.isEmpty() && !afterafter) {
        mongo_q = QUERY( "domain_id" << id << "auth" << true << "ordername" << BSON("$gt" << "")) ;
        afterafter = true;
        goto retryAfter;
    }

    after = mongo_r.getStringField("ordername");

    if(logging_content)
        L<<Logger::Info << backend_name << "(getBeforeAndAfterNamesAbsolute) after record '" << mongo_r.toString() << "'" << endl;

    bool beforebefore = false;

    fields = BSON("name" << 1 << "ordername" << 1);

retryBefore:
    mongo_q = QUERY( "domain_id" << id << "auth" << true << "ordername" << BSON("$lte" << lqname)) ;

    if(logging)
        L<<Logger::Info << backend_name << "(getBeforeAndAfterNamesAbsolute) Query before: '"<< mongo_q.toString() << "'" << endl;

    mongo_q.hint(BSON("domain_id" << 1 << "auth" << 1 << "ordername" << -1));

    mongo_c = m_db.query(collection_records, mongo_q, 0, 0, &fields);

    if (!mongo_c->more() && !beforebefore) {
	lqname = "{";
	beforebefore = true;
	goto retryBefore;
    }

    if (mongo_c->more()) {
        mongo_r = mongo_c->next();

	if(logging_content)
	    L<<Logger::Info << backend_name << "(getBeforeAndAfterNamesAbsolute) before next record 1 '" << mongo_r.toString() << "'" << endl;
	
	if (mongo_c->more())
	    mongo_r = mongo_c->next();

	if(logging_content)
	    L<<Logger::Info << backend_name << "(getBeforeAndAfterNamesAbsolute) before next record 2 '" << mongo_r.toString() << "'" << endl;

	before = mongo_r.getStringField("ordername");
	unhashed = mongo_r.getStringField("name");

	if(logging)
	    L<<Logger::Info << backend_name << "(getBeforeAndAfterNamesAbsolute) END unhashed: '" << unhashed << "' before: '" << before << "' after: '" << after << "' " << endl;
	
	return true;
	
    } else {
        L<<Logger::Error << backend_name << "(getBeforeAndAfterNamesAbsolute) Did not get any result for the 'before' query: '"<< mongo_q.toString() << "'" << endl;
	return false;
    }
}


int MONGODBBackend::addDomainKey(const string& name, const KeyData& key) {
// there is no logging function in pdnssec when running this routine?

    if (!dnssec)
	return false;
	
    DomainInfo di;

    if (!getDomainInfo(name, di, NULL))
	return -1;

    //we are using this to generate an unique id since 
    //mongodb does not have an autoinc type with global locking.

    unsigned int id = generateCRC32(name + key.content);

    bson::bo update1 = BSON( "name" << name << "domain_id" << di.id );
    bson::bo update2 = BSON( "$push" << BSON("content" << BSON("id" << id << "flags" << key.flags << "active" << key.active << "data" << key.content) ) );

    if(logging_cerr) {
        cerr << backend_name << "(addDomainKey) Query: '"<< update1.toString() << "'" << endl;
	if(logging_content) 
    	    cerr << backend_name << "(addDomainKey) Update: '"<< update2.toString() << "'" << endl;
    }

    mongo::BSONObj mongo_r = m_db.findOne(collection_cryptokeys, update1 );
    if (mongo_r.isEmpty()) 
	m_db.insert(collection_cryptokeys, update1);
	
    string m_error = m_db.getLastError();

    if(logging_cerr && !m_error.empty())
	cerr << backend_name << "(addDomainKey) getLastError1: "<< m_error << endl;

    m_db.update(collection_cryptokeys, update1 , update2);

    m_error = m_db.getLastError();

    if(logging_cerr && !m_error.empty())
	cerr << backend_name << "(addDomainKey) getLastError2: "<< m_error << endl;

    return 1; //or id ??
}

bool MONGODBBackend::getTSIGKey(const string& name, string* algorithm, string* content) { 
    if (!dnssec)
	return false;

    mongo::Query mongo_q = QUERY( "name" << name << "content.algorithm" << *algorithm);

    if(logging)
        L<<Logger::Info << backend_name << "(getTSIGKey) Query: '"<< mongo_q.toString() << "'" << endl;

    mongo::BSONObj mongo_r = m_db.findOne(collection_tsigkeys, mongo_q );

    if (mongo_r.isEmpty()) 
        return false;

    if (!mongo_r.hasElement("content.$.secret")) {
        L<<Logger::Error << backend_name << "(getTSIGKey) The record '" << mongo_r.toString() << "' is missing the data for the query: '"<< mongo_q.toString() << "'" << endl;
        return false;
    }

    *content = mongo_r.getStringField("content.$.secret");

    return !content->empty(); 
}

bool MONGODBBackend::changeDomainKey(const string& name, unsigned int &id, bool toowhat ) {
    if (!dnssec)
	return false;

    mongo::Query mongo_q = QUERY( "name" << name << "content.id" << id);
    bson::bo update = BSON( "$set" << BSON("content.$.active" << toowhat) );

    string f_name = toowhat ? "(activateDomainKey)" : "(deactivateDomainKey)";

    if(logging) {
        L<<Logger::Info << backend_name << f_name << " Query: '"<< mongo_q.toString() << "'" << endl;
	if(logging_content) 
    	    L<<Logger::Info << backend_name << f_name << " Update: '"<< update.toString() << "'" << endl;
    }

    if(logging_cerr) {
        cerr << backend_name << f_name << " Query: '"<< mongo_q.toString() << "'" << endl;
	if(logging_content) 
    	    cerr << backend_name << f_name << " Update: '"<< update.toString() << "'" << endl;
    }

    m_db.update(collection_cryptokeys, mongo_q , update, false);

    return true; //?? how do we know that ??
}

bool MONGODBBackend::activateDomainKey(const string& name, unsigned int id) {

    return changeDomainKey(name, id, true);

}

bool MONGODBBackend::deactivateDomainKey(const string& name, unsigned int id) {

    return changeDomainKey(name, id, false);

}

bool MONGODBBackend::removeDomainKey(const string& name, unsigned int id) {
    if (!dnssec)
	return false;

    mongo::Query mongo_q = QUERY( "name" << name << "content.id" << id);
    bson::bo update = BSON("$pop" << BSON("content" << "$") );

    if(logging) {
        L<<Logger::Info << backend_name << "(removeDomainKey)" << " Query: '"<< mongo_q.toString() << "'" << endl;
	if(logging_content) 
    	    L<<Logger::Info << backend_name << "(removeDomainKey)" << " Update: '"<< update.toString() << "'" << endl;
    }

    if(logging_cerr) {
        cerr << backend_name << "(removeDomainKey)" << " Query: '"<< mongo_q.toString() << "'" << endl;
	if(logging_content) 
    	    cerr << backend_name << "(removeDomainKey)" << " Update: '"<< update.toString() << "'" << endl;
    }

    m_db.update(collection_cryptokeys, mongo_q, update );

    if(logging_cerr) 
	cerr << backend_name << "(removeDomainKey) getLastError: "<< m_db.getLastError()<< endl;
    
    return true; //?? how do we know that ??
}

bool MONGODBBackend::getDomainKeys(const string& name, unsigned int kind, std::vector<KeyData>& keys) {
    //what is kind used for?

    if (!dnssec)
	return false;
	
    mongo::Query mongo_q = QUERY( "name" << name);

    if(logging)
        L<<Logger::Info << backend_name << "(getDomainKeys)" << " Query: '"<< mongo_q.toString() << "'" << endl;

    mongo::BSONObj mongo_r = m_db.findOne(collection_cryptokeys, mongo_q );

    if (mongo_r.isEmpty())
	return false;

    int c = 0;

    if(mongo_r.hasElement("content")) {
	for( bson::bo::iterator i(mongo_r.getObjectField("content")); i.more(); ) {
    	    bson::bo o1, o2;
    	    o1 = i.next().wrap();
    	    o2 = o1.firstElement().embeddedObject();
		
	    if(o2.hasElement("id") && o2.hasElement("flags") && o2.hasElement("active") && o2.hasElement("data")) {
    	        c++;
	        KeyData kd;
		
	        kd.id = o2.getIntField("id");
	        kd.flags = o2.getIntField("flags");
	        kd.active = o2.getBoolField("active");
	        kd.content = o2.getStringField("data");
		
	        keys.push_back(kd);
		
	    } else {
	        L<<Logger::Error << backend_name << "(getDomainKeys) The contents '" << o2.toString() << "' is missing the id/flags/active/data field for the record '" << mongo_r.toString() << "'" << endl;
	        c--;
	    }
    	}
    } else {
        L<<Logger::Error << backend_name << "(getDomainKeys) The record '" << mongo_r.toString() << "' is missing the content for the query: '"<< mongo_q.toString() << "'" << endl;
    }

    return c > 0;
}

bool MONGODBBackend::setDomainMetadata(const string& name, const std::string& kind, std::vector<std::string>& meta) {
    if (!dnssec)
	return false;

    mongo::Query mongo_q1 = QUERY( "name" << name << "content.kind" << kind);

    if(logging)
        L<<Logger::Info << backend_name << "(setDomainMetadata) Query: '"<< mongo_q1.toString() << "'" << endl;

    bson::bo mongo_q2 = BSON( "name" << name);

    mongo::BSONObj mongo_r = m_db.findOne(collection_domainmetadata, mongo_q2 );
    if (mongo_r.isEmpty()) 
	m_db.insert(collection_domainmetadata, mongo_q2 );


    bson::bo update1 = BSON("$pop" << BSON("content" << "$") );
    m_db.update(collection_domainmetadata, mongo_q1, update1 );

    string m_error = m_db.getLastError();

    if(logging_cerr && !m_error.empty())
	cerr << backend_name << "(setDomainMetadata) getLastError1: "<< m_error << endl;

    if (meta.empty()) {
	return true; //?
    }

    std::vector<std::string>::iterator i;

    mongo::BSONArrayBuilder contents;

    for(i = meta.begin(); i<meta.end(); i++ ) {
	contents.append(*i);
    }

    bson::bo update2 = BSON( "$push" << BSON("content" << BSON("kind" << kind << "data" << contents.arr() ) ) );

    if(logging_content) 
        L<<Logger::Info << backend_name << "(setDomainMetadata) Update: '"<< update2.toString() << "'" << endl;

    m_db.update(collection_domainmetadata, mongo_q1 , update2, true);

    m_error = m_db.getLastError();

    if(logging_cerr && !m_error.empty())
	cerr << backend_name << "(setDomainMetadata) getLastError2: "<< m_error << endl;

    return true;
}

bool MONGODBBackend::getDomainMetadata(const string& name, const std::string& kind, std::vector<std::string>& meta, set<string> *ips) {
    if (!dnssec)
	return false;
	
    mongo::Query mongo_q = QUERY( "name" << name << "content.kind" << kind);

    if(logging)
        L<<Logger::Info << backend_name << "(getDomainMetadata) Query: '"<< mongo_q.toString() << "'" << endl;

    mongo::BSONObj mongo_r = m_db.findOne(collection_domainmetadata, mongo_q );

    if (mongo_r.isEmpty()) 
        return false;

    if (!mongo_r.hasElement("content.$.data")) {
        L<<Logger::Error << backend_name << "(getDomainMetadata) The record '" << mongo_r.toString() << "' is missing the data for the query: '"<< mongo_q.toString() << "'" << endl;
        return false;
    }

    int c = 0;

    if (ips == NULL) 
	for( bson::bo::iterator i(mongo_r.getObjectField("content.$.data")); i.more(); ) {
    	    bson::bo o;
    	    bson::be e;
    	    o = i.next().wrap();
    	    e = o.firstElement();
    	    meta.push_back(e.valuestr());
    	    c++;
	}
    else 
	for( bson::bo::iterator i(mongo_r.getObjectField("content.$.data")); i.more(); ) {
    	    bson::bo o;
    	    bson::be e;
    	    o = i.next().wrap();
    	    e = o.firstElement();
    	    ips->insert(e.valuestr());
    	    c++;
	}

    return c > 0;
}

void MONGODBBackend::alsoNotifies(const string &domain, set<string> *ips) {
    if (!dnssec)
	return;
	
    string kind = "ALSO-NOTIFY";
    std::vector<std::string> meta;

    getDomainMetadata(domain, kind, meta , ips);
}
