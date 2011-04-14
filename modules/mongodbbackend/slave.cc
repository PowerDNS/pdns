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
    //transaction is not yet implemented in this backend
    
   virtual bool startTransaction(const string &qname, int id);
   virtual bool commitTransaction();
   virtual bool abortTransaction();
   virtual bool feedRecord(const DNSResourceRecord &rr);

   virtual bool getDomainInfo(const string &domain, DomainInfo &di);
   virtual bool isMaster(const string &name, const string &ip);
   virtual void getUnfreshSlaveInfos(vector<DomainInfo>* domains);
   virtual void setFresh(int id);
*/

void MONGODBBackend::setFresh(int id) {
    mongo::Query mongo_q = QUERY( "domain_id" << id );
    bson::bo update = BSON( "$set" << BSON("last_check" << (unsigned int) time(0) ) );

    if(logging) {
        L<<Logger::Info << backend_name << "(setFresh)" << " Query: "<< mongo_q.toString() << endl;
	if(logging_content)
    	    L<<Logger::Info << backend_name << "(setFresh)" << " Update: "<< update.toString() << endl;
    }
    
    m_db.update(collection_domains, mongo_q , update, false );
}

void MONGODBBackend::getUnfreshSlaveInfos(vector<DomainInfo>* domains) {
    //please see the function getTheFreshOnes in private.cc
    
    string type = "SLAVE";
    string f_name = "(getUnfreshSlaveInfos)";
    
    getTheFreshOnes(domains, &type, &f_name);
}

bool MONGODBBackend::isMaster(const string &domain, const string &ip) {

    mongo::Query mongo_q = QUERY( "name" << toLower(domain) );

    mongo::BSONObj mongo_r = m_db.findOne(collection_domains, mongo_q );

    string f_name = "(isMaster)";
    
    string m_q = mongo_q.toString();
    
    if(logging)
        L<<Logger::Info << backend_name << f_name << " Query: "<< m_q << endl;

    if (mongo_r.isEmpty()) 
	return false;

    DomainInfo di;
    
    if(!checkDomainInfo(&domain, &mongo_r, &f_name, &m_q, &di))
	return false;
    
    for(vector<string>::const_iterator iter=di.masters.begin(); iter != di.masters.end(); ++iter) {
	// we can also have masters with a port specified (which we ignore here)
	ServiceTuple st;
        parseService(*iter, st);
        if (!strcmp(ip.c_str(), st.host.c_str())) {
    	    return true;
        }
    }
    
    return false;
}

bool MONGODBBackend::getDomainInfo(const string &domain, DomainInfo &di, SOAData *soadata, unsigned int domain_id) {

    mongo::Query mongo_q;

    if (domain_id > 0)
	mongo_q = QUERY( "domain_id" << domain_id );
    else 
	mongo_q = QUERY( "name" << toLower(domain) );

    mongo::BSONObj mongo_r = m_db.findOne(collection_domains, mongo_q );

    string f_name = soadata == NULL ? "(getDomainInfo)" : "(getSOA)";
    
    string m_q = mongo_q.toString();
    
    if(logging)
        L<<Logger::Info << backend_name << f_name << " Query: "<< m_q << endl;

    if (mongo_r.isEmpty()) 
	return false;
    
    return checkDomainInfo(&domain, &mongo_r, &f_name, &m_q, &di, soadata);
}
