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
    virtual void getUpdatedMasters(vector<DomainInfo>* domains);
    virtual void setNotifed(int id, u_int32_t serial);
*/

void MONGODBBackend::getUpdatedMasters(vector<DomainInfo>* domains) {
    //please see the function getTheFreshOnes in private.cc 
    
    string type = "MASTER";
    string f_name = "(getUpdatedMasters)";
    
    getTheFreshOnes(domains, &type, &f_name);
}

void MONGODBBackend::setNotifed(int id, u_int32_t serial) {
    mongo::Query mongo_q = QUERY( "domain_id" << id );
    bson::bo update = BSON( "$set" << BSON("notified_serial" << serial ));

    if(logging) {
        L<<Logger::Info << backend_name << "(setNotifed)" << " Query: "<< mongo_q.toString() << endl;
	if(logging_content) 
	    L<<Logger::Info << backend_name << "(setNotifed)" << " Update: "<< update.toString() << endl;
    }
    
    m_db.update(collection_domains, mongo_q , update, false );
}

