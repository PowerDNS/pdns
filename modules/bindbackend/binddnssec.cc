/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002-2012  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2
    as published by the Free Software Foundation

    Additionally, the license of this program contains a special
    exception which allows to distribute the program in binary form when
    it is linked against OpenSSL.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "bindbackend2.hh"
#include "pdns/dnsrecords.hh"
#include "pdns/bind-dnssec.schema.sqlite3.sql.h"
#include <boost/foreach.hpp>
#include "pdns/arguments.hh"

#ifndef HAVE_SQLITE3
void Bind2Backend::setupDNSSEC()
{
  if(!getArg("dnssec-db").empty())
    throw runtime_error("bind-dnssec-db requires building PowerDNS with SQLite3");
}

bool Bind2Backend::doesDNSSEC()
{ return d_hybrid; }

bool Bind2Backend::getNSEC3PARAM(const std::string& zname, NSEC3PARAMRecordContent* ns3p)
{ return false; }

bool Bind2Backend::getAllDomainMetadata(const string& name, std::map<std::string, std::vector<std::string> >& meta)
{ return false; }

bool Bind2Backend::getDomainMetadata(const string& name, const std::string& kind, std::vector<std::string>& meta)
{ return false; }

bool Bind2Backend::setDomainMetadata(const string& name, const std::string& kind, const std::vector<std::string>& meta)
{ return false; }

bool Bind2Backend::getDomainKeys(const string& name, unsigned int kind, std::vector<KeyData>& keys)
{ return false; }

bool Bind2Backend::removeDomainKey(const string& name, unsigned int id)
{ return false; }

int Bind2Backend::addDomainKey(const string& name, const KeyData& key)
{ return -1; }

bool Bind2Backend::activateDomainKey(const string& name, unsigned int id)
{ return false; }

bool Bind2Backend::deactivateDomainKey(const string& name, unsigned int id)
{ return false; }

bool Bind2Backend::getTSIGKey(const string& name, string* algorithm, string* content)
{ return false; }

bool Bind2Backend::setTSIGKey(const string& name, const string& algorithm, const string& content)
{ return false; }

bool Bind2Backend::deleteTSIGKey(const string& name)
{ return false; }

bool Bind2Backend::getTSIGKeys(std::vector< struct TSIGKey > &keys)
{ return false; }
void Bind2Backend::setupStatements() 
{ return; }
void Bind2Backend::freeStatements()
{ return; }

#else

#include "pdns/ssqlite3.hh"
void Bind2Backend::setupDNSSEC()
{
  // cerr<<"Settting up dnssec db.. "<<getArg("dnssec-db") <<endl;
  if(getArg("dnssec-db").empty() || d_hybrid)
    return;
  try {
    d_dnssecdb = shared_ptr<SSQLite3>(new SSQLite3(getArg("dnssec-db")));
    setupStatements();
  }
  catch(SSqlException& se) {
    // this error is meant to kill the server dead - it makes no sense to continue..
    throw runtime_error("Error opening DNSSEC database in BIND backend: "+se.txtReason());
  }

  d_dnssecdb->setLog(::arg().mustDo("query-logging"));
}

void Bind2Backend::setupStatements() 
{
  d_getAllDomainMetadataQuery_stmt = d_dnssecdb->prepare("select kind, content from domainmetadata where domain=:domain",1);
  d_getDomainMetadataQuery_stmt = d_dnssecdb->prepare("select content from domainmetadata where domain=:domain and kind=:kind",2);
  d_deleteDomainMetadataQuery_stmt = d_dnssecdb->prepare("delete from domainmetadata where domain=:domain and kind=:kind",2);
  d_insertDomainMetadataQuery_stmt = d_dnssecdb->prepare("insert into domainmetadata (domain, kind, content) values (:domain,:kind,:content)",3);
  d_getDomainKeysQuery_stmt = d_dnssecdb->prepare("select id,flags, active, content from cryptokeys where domain=:domain",1);
  d_deleteDomainKeyQuery_stmt = d_dnssecdb->prepare("delete from cryptokeys where domain=:domain and id=:key_id",2);
  d_insertDomainKeyQuery_stmt = d_dnssecdb->prepare("insert into cryptokeys (domain, flags, active, content) values (:domain, :flags, :active, :content)", 4);
  d_activateDomainKeyQuery_stmt = d_dnssecdb->prepare("update cryptokeys set active=1 where domain=:domain and id=:key_id", 2);
  d_deactivateDomainKeyQuery_stmt = d_dnssecdb->prepare("update cryptokeys set active=0 where domain=:domain and id=:key_id", 2);
  d_getTSIGKeyQuery_stmt = d_dnssecdb->prepare("select algorithm, secret from tsigkeys where name=:key_name", 1);
  d_setTSIGKeyQuery_stmt = d_dnssecdb->prepare("replace into tsigkeys (name,algorithm,secret) values(:key_name, :algorithm, :content)", 3);
  d_deleteTSIGKeyQuery_stmt = d_dnssecdb->prepare("delete from tsigkeys where name=:key_name", 1);
  d_getTSIGKeysQuery_stmt = d_dnssecdb->prepare("select name,algorithm,secret from tsigkeys", 0);
}

void Bind2Backend::release(SSqlStatement** stmt) {
  delete *stmt;
  *stmt = NULL;
}

void Bind2Backend::freeStatements() 
{
    release(&d_getAllDomainMetadataQuery_stmt);
    release(&d_getDomainMetadataQuery_stmt);
    release(&d_deleteDomainMetadataQuery_stmt);
    release(&d_insertDomainMetadataQuery_stmt);
    release(&d_getDomainKeysQuery_stmt);
    release(&d_deleteDomainKeyQuery_stmt);
    release(&d_insertDomainKeyQuery_stmt);
    release(&d_activateDomainKeyQuery_stmt);
    release(&d_deactivateDomainKeyQuery_stmt);
    release(&d_getTSIGKeyQuery_stmt);
    release(&d_setTSIGKeyQuery_stmt);
    release(&d_deleteTSIGKeyQuery_stmt);
    release(&d_getTSIGKeysQuery_stmt);
}
bool Bind2Backend::doesDNSSEC()
{
  return d_dnssecdb || d_hybrid;
}

bool Bind2Backend::getNSEC3PARAM(const std::string& zname, NSEC3PARAMRecordContent* ns3p)
{
  if(!d_dnssecdb || d_hybrid)
    return false;

  string value;
  vector<string> meta;
  getDomainMetadata(zname, "NSEC3PARAM", meta);
  if(!meta.empty())
    value=*meta.begin();
  
  if(value.empty()) { // "no NSEC3"
    return false;
  }
     
  if(ns3p) {
    NSEC3PARAMRecordContent* tmp=dynamic_cast<NSEC3PARAMRecordContent*>(DNSRecordContent::mastermake(QType::NSEC3PARAM, 1, value));
    *ns3p = *tmp;
    delete tmp;
  }
  return true;
}

bool Bind2Backend::getAllDomainMetadata(const string& name, std::map<std::string, std::vector<std::string> >& meta)
{
  if(!d_dnssecdb || d_hybrid)
    return false;

  // cerr<<"Asked to get metadata for zone '"<<name<<"'|"<<kind<<"\n";

  try {
    d_getAllDomainMetadataQuery_stmt->
      bind("domain", name)->
      execute();

    SSqlStatement::row_t row;
    while(d_getAllDomainMetadataQuery_stmt->hasNextRow()) {
      d_getAllDomainMetadataQuery_stmt->nextRow(row);
      meta[row[0]].push_back(row[1]);
    }

    d_getAllDomainMetadataQuery_stmt->reset();
  }
  catch(SSqlException& se) {
    throw PDNSException("Error accessing DNSSEC database in BIND backend: "+se.txtReason());
  }
  return true;
}

bool Bind2Backend::getDomainMetadata(const string& name, const std::string& kind, std::vector<std::string>& meta)
{
  if(!d_dnssecdb || d_hybrid)
    return false;
    
  // cerr<<"Asked to get metadata for zone '"<<name<<"'|"<<kind<<"\n";
  
  try {
    d_getDomainMetadataQuery_stmt->
      bind("domain", name)->
      bind("kind", kind)->
      execute(); 
  
    SSqlStatement::row_t row;
    while(d_getDomainMetadataQuery_stmt->hasNextRow()) {
      d_getDomainMetadataQuery_stmt->nextRow(row);
      meta.push_back(row[0]);
    }

    d_getDomainMetadataQuery_stmt->reset();
  }
  catch(SSqlException& se) {
    throw PDNSException("Error accessing DNSSEC database in BIND backend: "+se.txtReason());
  }
  return true;
}

bool Bind2Backend::setDomainMetadata(const string& name, const std::string& kind, const std::vector<std::string>& meta)
{
  if(!d_dnssecdb || d_hybrid)
    return false;
  
  try {
    d_deleteDomainMetadataQuery_stmt->
      bind("domain", name)->
      bind("kind", kind)->
      execute()->
      reset();
    if(!meta.empty()) {
      BOOST_FOREACH(const string& value, meta) {
        d_insertDomainMetadataQuery_stmt->
          bind("domain", name)->
          bind("kind", kind)->
          bind("content", value)->
          execute()->
          reset();
      }
    }
  }
  catch(SSqlException& se) {
    throw PDNSException("Error accessing DNSSEC database in BIND backend: "+se.txtReason());
  }
  return true;

}

bool Bind2Backend::getDomainKeys(const string& name, unsigned int kind, std::vector<KeyData>& keys)
{
  // cerr<<"Asked to get keys for zone '"<<name<<"'\n";
  if(!d_dnssecdb || d_hybrid)
    return false;
  try {
    d_getDomainKeysQuery_stmt->
      bind("domain", name)->
      execute();
    KeyData kd;
    SSqlStatement::row_t row;
    while(d_getDomainKeysQuery_stmt->hasNextRow()) {
      d_getDomainKeysQuery_stmt->nextRow(row);
      kd.id = atoi(row[0].c_str());
      kd.flags = atoi(row[1].c_str());
      kd.active = atoi(row[2].c_str());
      kd.content = row[3];
      keys.push_back(kd);
    }
    d_getDomainKeysQuery_stmt->reset();
  }
  catch(SSqlException& se) {
    throw PDNSException("Error accessing DNSSEC database in BIND backend: "+se.txtReason());
  }
  
  return true;
}

bool Bind2Backend::removeDomainKey(const string& name, unsigned int id)
{
  if(!d_dnssecdb || d_hybrid)
    return false;

  // cerr<<"Asked to remove key "<<id<<" in zone '"<<name<<"'\n";

  try {
    d_deleteDomainKeyQuery_stmt->
      bind("domain", name)->
      bind("key_id", id)->
      execute()->
      reset();
  }
  catch(SSqlException& se) {
    cerr<<se.txtReason()  <<endl;
  }
  
  return true;
}

int Bind2Backend::addDomainKey(const string& name, const KeyData& key)
{
  if(!d_dnssecdb || d_hybrid)
    return -1;
  
  //cerr<<"Asked to add a key to zone '"<<name<<"'\n";
  
  try {
    d_insertDomainKeyQuery_stmt->
      bind("domain", name)->
      bind("flags", key.flags)->
      bind("active", key.active)->
      bind("content", key.content)->
      execute()->
      reset();
  }
  catch(SSqlException& se) {
    throw PDNSException("Error accessing DNSSEC database in BIND backend: "+se.txtReason());    
  }
  
  return true;
}

bool Bind2Backend::activateDomainKey(const string& name, unsigned int id)
{
  // cerr<<"Asked to activate key "<<id<<" inzone '"<<name<<"'\n";
  if(!d_dnssecdb || d_hybrid)
    return false;
  
  try {
    d_activateDomainKeyQuery_stmt->
      bind("domain", name)->
      bind("key_id", id)->
      execute()->
      reset();
  }
  catch(SSqlException& se) {
    throw PDNSException("Error accessing DNSSEC database in BIND backend: "+se.txtReason());    
  }
  
  return true;
}

bool Bind2Backend::deactivateDomainKey(const string& name, unsigned int id)
{
  // cerr<<"Asked to deactivate key "<<id<<" inzone '"<<name<<"'\n";
  if(!d_dnssecdb || d_hybrid)
    return false;
    
  try {
    d_deactivateDomainKeyQuery_stmt->
      bind("domain", name)->
      bind("key_id", id)->
      execute()->
      reset();
  }
  catch(SSqlException& se) {
    throw PDNSException("Error accessing DNSSEC database in BIND backend: "+se.txtReason());
  }
  
  return true;
}

bool Bind2Backend::getTSIGKey(const string& name, string* algorithm, string* content)
{
  if(!d_dnssecdb || d_hybrid)
    return false;
  
  try {
    d_getTSIGKeyQuery_stmt->
      bind("key_name", name)->
      execute();
    SSqlStatement::row_t row;
    content->clear();
    while(d_getTSIGKeyQuery_stmt->hasNextRow()) {
      d_getTSIGKeyQuery_stmt->nextRow(row);
      if(row.size() >= 2 && (algorithm->empty() || pdns_iequals(*algorithm, row[0]))) {
        *algorithm = row[0];
        *content = row[1];
      }
    }
    d_getTSIGKeyQuery_stmt->reset();
  }
  catch (SSqlException &e) {
    throw PDNSException("BindBackend unable to retrieve named TSIG key: "+e.txtReason());
  }

  return !content->empty();
}

bool Bind2Backend::setTSIGKey(const string& name, const string& algorithm, const string& content)
{
  if(!d_dnssecdb || d_hybrid)
    return false;

  try {
    d_setTSIGKeyQuery_stmt->
      bind("key_name", name)->
      bind("algorithm", algorithm)->
      bind("content", content)->
      execute()->
      reset();
  }
  catch (SSqlException &e) {
    throw PDNSException("BindBackend unable to retrieve named TSIG key: "+e.txtReason());
  }

  return true;
}

bool Bind2Backend::deleteTSIGKey(const string& name) 
{
  if(!d_dnssecdb || d_hybrid)
    return false;

  try {
    d_deleteTSIGKeyQuery_stmt->
      bind("key_name", name)->
      execute()->
      reset();
  }
  catch (SSqlException &e) {
    throw PDNSException("BindBackend unable to retrieve named TSIG key: "+e.txtReason());
  }

  return true;
}

bool Bind2Backend::getTSIGKeys(std::vector< struct TSIGKey > &keys)
{
  if(!d_dnssecdb || d_hybrid)
    return false;

  try {
    d_getTSIGKeysQuery_stmt->
      execute(); 

    SSqlStatement::row_t row;

    while(d_getTSIGKeysQuery_stmt->hasNextRow()) {
      d_getTSIGKeysQuery_stmt->nextRow(row);
      struct TSIGKey key;
      key.name = row[0];
      key.algorithm = row[1];
      key.key = row[2];
      keys.push_back(key);
    }

    d_getTSIGKeysQuery_stmt->reset();
  }
  catch (SSqlException &e) {
    throw PDNSException("GSQLBackend unable to retrieve all TSIG keys: "+e.txtReason());
  }

  return !keys.empty();
}


#endif
