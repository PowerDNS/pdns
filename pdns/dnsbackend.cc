/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * In addition, for the avoidance of any doubt, permission is granted to
 * link this program with OpenSSL and to (re)distribute the binaries
 * produced as the result of such linking.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "utility.hh"
#include "dnsbackend.hh"
#include "arguments.hh"
#include "ueberbackend.hh"
#include "logger.hh"

#include <sys/types.h>
#include "packetcache.hh"
#include "auth-zonecache.hh"
#include "dnspacket.hh"
#include "dns.hh"
#include "statbag.hh"

extern StatBag S;

// this has to be somewhere central, and not in a file that requires Lua
// this is so the geoipbackend can set this pointer if loaded for lua-record.cc
std::function<std::string(const std::string&, int)> g_getGeo;

bool DNSBackend::getAuth(const DNSName &target, SOAData *sd)
{
  return this->getSOA(target, *sd);
}

void DNSBackend::setArgPrefix(const string &prefix)
{
  d_prefix=prefix;
}

bool DNSBackend::mustDo(const string &key)
{
  return arg().mustDo(d_prefix+"-"+key);
}

const string &DNSBackend::getArg(const string &key)
{
  return arg()[d_prefix+"-"+key];
}

int DNSBackend::getArgAsNum(const string &key)
{
  return arg().asNum(d_prefix+"-"+key);
}

void BackendFactory::declare(const string &suffix, const string &param, const string &help, const string &value)
{
  string fullname=d_name+suffix+"-"+param;
  arg().set(fullname,help)=value;
  arg().setDefault(fullname,value);
}

const string &BackendFactory::getName() const
{
  return d_name;
}

BackendMakerClass &BackendMakers()
{
  static BackendMakerClass bmc;
  return bmc;
}

void BackendMakerClass::report(BackendFactory *bf)
{
  d_repository[bf->getName()]=bf;
}

void BackendMakerClass::clear()
{
  d_instances.clear();
  for (auto& repo : d_repository) {
    delete repo.second;
    repo.second = nullptr;
  }
  d_repository.clear();
}

vector<string> BackendMakerClass::getModules()
{
  load_all();
  vector<string> ret;
  //  copy(d_repository.begin(), d_repository.end(),back_inserter(ret));
  for(d_repository_t::const_iterator i=d_repository.begin();i!=d_repository.end();++i)
    ret.push_back(i->first);
  return ret;
}

void BackendMakerClass::load_all()
{
  // TODO: Implement this?
  DIR *dir=opendir(arg()["module-dir"].c_str());
  if(!dir) {
    g_log<<Logger::Error<<"Unable to open module directory '"<<arg()["module-dir"]<<"'"<<endl;
    return;
  }
  struct dirent *entry;
  while((entry=readdir(dir))) {
    if(!strncmp(entry->d_name,"lib",3) &&
       strlen(entry->d_name)>13 &&
       !strcmp(entry->d_name+strlen(entry->d_name)-10,"backend.so"))
      load(entry->d_name);
  }
  closedir(dir);
}

void BackendMakerClass::load(const string &module)
{
  bool res;

  if(module.find('.')==string::npos)
    res=UeberBackend::loadmodule(arg()["module-dir"]+"/lib"+module+"backend.so");
  else if(module[0]=='/' || (module[0]=='.' && module[1]=='/') || (module[0]=='.' && module[1]=='.'))    // absolute or current path
    res=UeberBackend::loadmodule(module);
  else
    res=UeberBackend::loadmodule(arg()["module-dir"]+"/"+module);

  if(res==false) {
    g_log<<Logger::Error<<"DNSBackend unable to load module in "<<module<<endl;
    exit(1);
  }
}

void BackendMakerClass::launch(const string &instr)
{
  //    if(instr.empty())
  // throw ArgException("Not launching any backends - nameserver won't function");

  vector<string> parts;
  stringtok(parts,instr,", ");

  for (const auto& part : parts)
    if (count(parts.begin(), parts.end(), part) > 1)
      throw ArgException("Refusing to launch multiple backends with the same name '" + part + "', verify all 'launch' statements in your configuration");

  for(const auto & part : parts) {
    string module, name;
    vector<string>pparts;
    stringtok(pparts,part,": ");
    module=pparts[0];
    if(pparts.size()>1)
      name="-"+pparts[1];

    if(d_repository.find(module)==d_repository.end()) {
      // this is *so* userfriendly
      load(module);
      if(d_repository.find(module)==d_repository.end())
        throw ArgException("Trying to launch unknown backend '"+module+"'");
    }
    d_repository[module]->declareArguments(name);
    d_instances.emplace_back(module, name);
  }
}

size_t BackendMakerClass::numLauncheable() const
{
  return d_instances.size();
}

vector<DNSBackend *> BackendMakerClass::all(bool metadataOnly)
{
  vector<DNSBackend *> ret;
  if(d_instances.empty())
    throw PDNSException("No database backends configured for launch, unable to function");

  ret.reserve(d_instances.size());

  try {
    for (const auto& instance : d_instances) {
      DNSBackend *made = nullptr;

      if (metadataOnly) {
        made = d_repository[instance.first]->makeMetadataOnly(instance.second);
      }
      else {
        made = d_repository[instance.first]->make(instance.second);
      }

      if (!made) {
        throw PDNSException("Unable to launch backend '" + instance.first + "'");
      }

      ret.push_back(made);
    }
  }
  catch(const PDNSException &ae) {
    g_log<<Logger::Error<<"Caught an exception instantiating a backend: "<<ae.reason<<endl;
    g_log<<Logger::Error<<"Cleaning up"<<endl;
    for (auto i : ret) {
      delete i;
    }
    throw;
  } catch(...) {
    // and cleanup
    g_log<<Logger::Error<<"Caught an exception instantiating a backend, cleaning up"<<endl;
    for (auto i : ret) {
      delete i;
    }
    throw;
  }

  return ret;
}

/** getSOA() is a function that is called to get the SOA of a domain. Callers should ONLY
    use getSOA() and not perform a lookup() themselves as backends may decide to special case
    the SOA record.

    Returns false if there is definitely no SOA for the domain. May throw a DBException
    to indicate that the backend is currently unable to supply an answer.

    WARNING: This function *may* fill out the db attribute of the SOAData, but then again,
    it may not! If you find a zero in there, you may have been handed a non-live and cached
    answer, in which case you need to perform a getDomainInfo call!

    \param domain Domain we want to get the SOA details of
    \param sd SOAData which is filled with the SOA details
    \param unmodifiedSerial bool if set, serial will be returned as stored in the backend (maybe 0)
*/
bool DNSBackend::getSOA(const DNSName &domain, SOAData &sd)
{
  this->lookup(QType(QType::SOA),domain,-1);
  S.inc("backend-queries");

  DNSResourceRecord rr;
  int hits=0;

  sd.db = nullptr;

  try {
    while (this->get(rr)) {
      if (rr.qtype != QType::SOA) {
        throw PDNSException("Got non-SOA record when asking for SOA, zone: '" + domain.toLogString() + "'");
      }
      hits++;
      sd.qname = domain;
      sd.ttl = rr.ttl;
      sd.db = this;
      sd.domain_id = rr.domain_id;
      fillSOAData(rr.content, sd);
    }
  }
  catch (...) {
    while (this->get(rr)) {
      ;
    }
    throw;
  }

  return hits;
}

bool DNSBackend::get(DNSZoneRecord& dzr)
{
  //  cout<<"DNSBackend::get(DNSZoneRecord&) called - translating into DNSResourceRecord query"<<endl;
  DNSResourceRecord rr;
  if(!this->get(rr))
    return false;
  dzr.auth = rr.auth;
  dzr.domain_id = rr.domain_id;
  dzr.scopeMask = rr.scopeMask;
  if(rr.qtype.getCode() == QType::TXT && !rr.content.empty() && rr.content[0]!='"')
    rr.content = "\""+ rr.content + "\"";
  try {
    dzr.dr = DNSRecord(rr);
  }
  catch(...) {
    while(this->get(rr));
    throw;
  }
  return true;
}

bool DNSBackend::getBeforeAndAfterNames(uint32_t id, const DNSName& zonename, const DNSName& qname, DNSName& before, DNSName& after)
{
  DNSName unhashed;
  bool ret = this->getBeforeAndAfterNamesAbsolute(id, qname.makeRelative(zonename).makeLowerCase(), unhashed, before, after);
  DNSName lczonename = zonename.makeLowerCase();
  before += lczonename;
  after += lczonename;
  return ret;
}

void DNSBackend::getAllDomains(vector<DomainInfo>* domains, bool getSerial, bool include_disabled)
{
  if (g_zoneCache.isEnabled()) {
    g_log << Logger::Error << "One of the backends does not support zone caching. Put zone-cache-refresh-interval=0 in the config file to disable this cache." << endl;
    exit(1);
  }
}

void fillSOAData(const DNSZoneRecord& in, SOAData& sd)
{
  sd.domain_id = in.domain_id;
  sd.ttl = in.dr.d_ttl;

  auto src=getRR<SOARecordContent>(in.dr);
  sd.nameserver = src->d_mname;
  sd.hostmaster = src->d_rname;
  sd.serial = src->d_st.serial;
  sd.refresh = src->d_st.refresh;
  sd.retry = src->d_st.retry;
  sd.expire = src->d_st.expire;
  sd.minimum = src->d_st.minimum;
}

std::shared_ptr<DNSRecordContent> makeSOAContent(const SOAData& sd)
{
    struct soatimes st;
    st.serial = sd.serial;
    st.refresh = sd.refresh;
    st.retry = sd.retry;
    st.expire = sd.expire;
    st.minimum = sd.minimum;
    return std::make_shared<SOARecordContent>(sd.nameserver, sd.hostmaster, st);
}

void fillSOAData(const string &content, SOAData &data)
{
  vector<string>parts;
  parts.reserve(7);
  stringtok(parts, content);

  try {
    data.nameserver = DNSName(parts.at(0));
    data.hostmaster = DNSName(parts.at(1));
    data.serial = pdns_stou(parts.at(2).c_str());
    data.refresh = pdns_stou(parts.at(3).c_str());
    data.retry = pdns_stou(parts.at(4).c_str());
    data.expire = pdns_stou(parts.at(5).c_str());
    data.minimum = pdns_stou(parts.at(6).c_str());
  }
  catch(const std::out_of_range& oor) {
    throw PDNSException("Out of range exception parsing '" + content + "'");
  }
}
