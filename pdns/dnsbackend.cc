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
#include "pdns/packetcache.hh"
#include "dnspacket.hh"
#include "dns.hh"

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

  if(module.find(".")==string::npos)
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

  for (const auto part : parts)
    if (count(parts.begin(), parts.end(), part) > 1)
      throw ArgException("Refusing to launch multiple backends with the same name '" + part + "', verify all 'launch' statements in your configuration");

  for(vector<string>::const_iterator i=parts.begin();i!=parts.end();++i) {
    const string &part=*i;

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
    d_instances.push_back(make_pair(module,name));
  }
}

int BackendMakerClass::numLauncheable()
{
  return d_instances.size();
}

vector<DNSBackend *>BackendMakerClass::all(bool metadataOnly)
{
  vector<DNSBackend *>ret;
  if(d_instances.empty())
    throw PDNSException("No database backends configured for launch, unable to function");

  try {
    for(vector<pair<string,string> >::const_iterator i=d_instances.begin();i!=d_instances.end();++i) {
      DNSBackend *made;
      if(metadataOnly)
        made = d_repository[i->first]->makeMetadataOnly(i->second);
      else
        made = d_repository[i->first]->make(i->second);
      if(!made)
        throw PDNSException("Unable to launch backend '"+i->first+"'");

      ret.push_back(made);
    }
  }
  catch(PDNSException &ae) {
    g_log<<Logger::Error<<"Caught an exception instantiating a backend: "<<ae.reason<<endl;
    g_log<<Logger::Error<<"Cleaning up"<<endl;
    for(vector<DNSBackend *>::const_iterator i=ret.begin();i!=ret.end();++i)
      delete *i;
    throw;
  } catch(...) {
    // and cleanup
    g_log<<Logger::Error<<"Caught an exception instantiating a backend, cleaning up"<<endl;
    for(vector<DNSBackend *>::const_iterator i=ret.begin();i!=ret.end();++i)
      delete *i;
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

  DNSResourceRecord rr;
  rr.auth = true;

  int hits=0;

  while(this->get(rr)) {
    if (rr.qtype != QType::SOA) throw PDNSException("Got non-SOA record when asking for SOA");
    hits++;
    fillSOAData(rr.content, sd);
    sd.domain_id=rr.domain_id;
    sd.ttl=rr.ttl;
  }

  if(!hits)
    return false;
  sd.qname = domain;
  if(!sd.nameserver.countLabels())
    sd.nameserver= DNSName(arg()["default-soa-name"]);

  if(!sd.hostmaster.countLabels()) {
    if (!arg().isEmpty("default-soa-mail")) {
      sd.hostmaster= DNSName(arg()["default-soa-mail"]);
      // attodot(sd.hostmaster); FIXME400
    }
    else
      sd.hostmaster=DNSName("hostmaster")+domain;
  }

  sd.db=this;
  return true;
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
  if(rr.qtype.getCode() == QType::SOA) {
    try {
      dzr.dr = DNSRecord(rr);
    } catch(...) {
      vector<string> parts;
      stringtok(parts, rr.content, " \t");
      if(parts.size() < 1)
        rr.content = arg()["default-soa-name"];
      if(parts.size() < 2)
        rr.content += " " +arg()["default-soa-mail"];
      if(parts.size() < 3)
        rr.content += " 0";
      if(parts.size() < 4)
        rr.content += " " + ::arg()["soa-refresh-default"];
      if(parts.size() < 5)
        rr.content += " " + ::arg()["soa-retry-default"];
      if(parts.size() < 6)
        rr.content += " " + ::arg()["soa-expire-default"];
      if(parts.size() < 7)
        rr.content += " " + ::arg()["soa-minimum-ttl"];
      dzr.dr = DNSRecord(rr);
    }
  }
  else {
    try {
      dzr.dr = DNSRecord(rr);
    }
    catch(...) {
      while(this->get(rr));
      throw;
    }
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
  sd.default_ttl = src->d_st.minimum;
}

std::shared_ptr<DNSRecordContent> makeSOAContent(const SOAData& sd)
{
    struct soatimes st;
    st.serial = sd.serial;
    st.refresh = sd.refresh;
    st.retry = sd.retry;
    st.expire = sd.expire;
    st.minimum = sd.default_ttl;
    return std::make_shared<SOARecordContent>(sd.nameserver, sd.hostmaster, st);
}


void fillSOAData(const string &content, SOAData &data)
{
  // content consists of fields separated by spaces:
  //  nameservername hostmaster serial-number [refresh [retry [expire [ minimum] ] ] ]

  // fill out data with some plausible defaults:
  // 10800 3600 604800 3600
  vector<string>parts;
  stringtok(parts,content);
  int pleft=parts.size();

  //  cout<<"'"<<content<<"'"<<endl;

  if(pleft)
    data.nameserver=DNSName(parts[0]);

  if(pleft>1) 
    data.hostmaster=DNSName(attodot(parts[1])); // ahu@ds9a.nl -> ahu.ds9a.nl, piet.puk@ds9a.nl -> piet\.puk.ds9a.nl

  try {
    data.serial = pleft > 2 ? pdns_stou(parts[2]) : 0;

    data.refresh = pleft > 3 ? pdns_stou(parts[3])
      : ::arg().asNum("soa-refresh-default");

    data.retry = pleft > 4 ? pdns_stou(parts[4].c_str())
      : ::arg().asNum("soa-retry-default");

    data.expire = pleft > 5 ? pdns_stou(parts[5].c_str())
      : ::arg().asNum("soa-expire-default");

    data.default_ttl = pleft > 6 ? pdns_stou(parts[6].c_str())
      : ::arg().asNum("soa-minimum-ttl");
  }
  catch(const std::out_of_range& oor) {
    throw PDNSException("Out of range exception parsing "+content);
  }
}
