/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002-2012  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2
    as published by the Free Software Foundation
    

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/
#include "bindbackend2.hh"
#include "dnsrecords.hh"
#include "bind-dnssec.schema.sqlite3.sql.h"
#include <boost/foreach.hpp>
#include "config.h"
#include "arguments.hh"

#ifndef HAVE_SQLITE3
void Bind2Backend::setupDNSSEC()
{
  if(!getArg("dnssec-db").empty())
    throw runtime_error("bind-dnssec-db requires building PowerDNS with SQLite3");
}

void Bind2Backend::createDNSSECDB(const string& fname)
{}

bool Bind2Backend::doesDNSSEC()
{ return false; }

bool Bind2Backend::getNSEC3PARAM(const std::string& zname, NSEC3PARAMRecordContent* ns3p)
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
{ return false; }

bool Bind2Backend::activateDomainKey(const string& name, unsigned int id)
{ return false; }

bool Bind2Backend::deactivateDomainKey(const string& name, unsigned int id)
{ return false; }

bool Bind2Backend::getTSIGKey(const string& name, string* algorithm, string* content)
{ return false; }
#else

#include "pdns/ssqlite3.hh"
void Bind2Backend::setupDNSSEC()
{
  // cerr<<"Settting up dnssec db.. "<<getArg("dnssec-db") <<endl;
  if(getArg("dnssec-db").empty())
    return;
  try {
    d_dnssecdb = shared_ptr<SSQLite3>(new SSQLite3(getArg("dnssec-db")));
  }
  catch(SSqlException& se) {
    // this error is meant to kill the server dead - it makes no sense to continue..
    throw runtime_error("Error opening DNSSEC database in BIND backend: "+se.txtReason());
  }

  d_dnssecdb->setLog(::arg().mustDo("query-logging"));
}

void Bind2Backend::createDNSSECDB(const string& fname)
{
  try {
    SSQLite3 db(fname, true); // create=ok
    vector<string> statements;
    stringtok(statements, sqlCreate, ";");
    BOOST_FOREACH(const string& statement, statements)
      db.doCommand(statement);
  }
  catch(SSqlException& se) {
    throw AhuException("Error creating database in BIND backend: "+se.txtReason());
  }
}

bool Bind2Backend::doesDNSSEC()
{
  return true;
}

bool Bind2Backend::getNSEC3PARAM(const std::string& zname, NSEC3PARAMRecordContent* ns3p)
{
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

bool Bind2Backend::getDomainMetadata(const string& name, const std::string& kind, std::vector<std::string>& meta)
{
  if(!d_dnssecdb)
    return false;
    
  // cerr<<"Asked to get metadata for zone '"<<name<<"'|"<<kind<<"\n";
  
  boost::format fmt("select content from domainmetadata where domain='%s' and kind='%s'");
  try {
    d_dnssecdb->doQuery((fmt % d_dnssecdb->escape(name) % d_dnssecdb->escape(kind)).str());
  
    vector<string> row;
    while(d_dnssecdb->getRow(row)) {
      meta.push_back(row[0]);
    }
  }
  catch(SSqlException& se) {
    throw AhuException("Error accessing DNSSEC database in BIND backend: "+se.txtReason());
  }
  return true;
}

bool Bind2Backend::setDomainMetadata(const string& name, const std::string& kind, const std::vector<std::string>& meta)
{
  if(!d_dnssecdb)
    return false;
  
  boost::format fmt("delete from domainmetadata where domain='%s' and kind='%s'");
  boost::format fmt2("insert into domainmetadata (domain, kind, content) values ('%s','%s', '%s')");
  try {
    d_dnssecdb->doCommand((fmt % d_dnssecdb->escape(name) % d_dnssecdb->escape(kind)).str());
    if(!meta.empty())
      d_dnssecdb->doCommand((fmt2 % d_dnssecdb->escape(name) % d_dnssecdb->escape(kind) % d_dnssecdb->escape(meta.begin()->c_str())).str());
  }
  catch(SSqlException& se) {
    throw AhuException("Error accessing DNSSEC database in BIND backend: "+se.txtReason());
  }
  return true;

}

bool Bind2Backend::getDomainKeys(const string& name, unsigned int kind, std::vector<KeyData>& keys)
{
  // cerr<<"Asked to get keys for zone '"<<name<<"'\n";
  if(!d_dnssecdb)
    return false;
  boost::format fmt("select id,flags, active, content from cryptokeys where domain='%s'");
  try {
    d_dnssecdb->doQuery((fmt % d_dnssecdb->escape(name)).str());
    KeyData kd;
    vector<string> row;
    while(d_dnssecdb->getRow(row)) {
      kd.id = atoi(row[0].c_str());
      kd.flags = atoi(row[1].c_str());
      kd.active = atoi(row[2].c_str());
      kd.content = row[3];
      keys.push_back(kd);
    }
  }
  catch(SSqlException& se) {
    throw AhuException("Error accessing DNSSEC database in BIND backend: "+se.txtReason());
  }
  
  return true;
}

bool Bind2Backend::removeDomainKey(const string& name, unsigned int id)
{
  if(!d_dnssecdb)
    return false;
  
  cerr<<"Asked to remove key "<<id<<" in zone '"<<name<<"'\n";
  
  boost::format fmt("delete from cryptokeys where domain='%s' and id=%d");
  try {
    d_dnssecdb->doCommand((fmt % d_dnssecdb->escape(name) % id).str());
  }
  catch(SSqlException& se) {
    cerr<<se.txtReason()  <<endl;
  }
  
  return true;
}

int Bind2Backend::addDomainKey(const string& name, const KeyData& key)
{
  if(!d_dnssecdb)
    return false;
  
  //cerr<<"Asked to add a key to zone '"<<name<<"'\n";
  
  boost::format fmt("insert into cryptokeys (domain, flags, active, content) values ('%s', %d, %d, '%s')");
  try {
    d_dnssecdb->doCommand((fmt % d_dnssecdb->escape(name) % key.flags % key.active % d_dnssecdb->escape(key.content)).str());
  }
  catch(SSqlException& se) {
    throw AhuException("Error accessing DNSSEC database in BIND backend: "+se.txtReason());    
  }
  
  return true;
}

bool Bind2Backend::activateDomainKey(const string& name, unsigned int id)
{
  // cerr<<"Asked to activate key "<<id<<" inzone '"<<name<<"'\n";
  if(!d_dnssecdb)
    return false;
  
  boost::format fmt("update cryptokeys set active=1 where domain='%s' and id=%d");
  try {
    d_dnssecdb->doCommand((fmt % d_dnssecdb->escape(name) % id).str());
  }
  catch(SSqlException& se) {
    throw AhuException("Error accessing DNSSEC database in BIND backend: "+se.txtReason());    
  }
  
  return true;
}

bool Bind2Backend::deactivateDomainKey(const string& name, unsigned int id)
{
  // cerr<<"Asked to deactivate key "<<id<<" inzone '"<<name<<"'\n";
  if(!d_dnssecdb)
    return false;
    
  boost::format fmt("update cryptokeys set active=0 where domain='%s' and id=%d");
  try {
    d_dnssecdb->doCommand((fmt % d_dnssecdb->escape(name) % id).str());
  }
  catch(SSqlException& se) {
    throw AhuException("Error accessing DNSSEC database in BIND backend: "+se.txtReason());
  }
  
  return true;
}

bool Bind2Backend::getTSIGKey(const string& name, string* algorithm, string* content)
{
  if(!d_dnssecdb)
    return false;
  boost::format fmt("select algorithm, secret from tsigkeys where name='%s'");
  
  try {
    d_dnssecdb->doQuery( (fmt % d_dnssecdb->escape(name)).str());
  }
  catch (SSqlException &e) {
    throw AhuException("BindBackend unable to retrieve named TSIG key: "+e.txtReason());
  }
  
  SSql::row_t row;
  
  content->clear();
  while(d_dnssecdb->getRow(row)) {
    *algorithm = row[0];
    *content=row[1];
  }

  return !content->empty();

}
#endif
