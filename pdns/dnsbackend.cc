/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/
#include "utility.hh"
#include "dnsbackend.hh"
#include "arguments.hh"
#include "ueberbackend.hh"
#include "logger.hh"

#include <sys/types.h>
#include "dnspacket.hh"

string DNSResourceRecord::serialize() const
{
  ostringstream ostr;
  ostr<<escape(qname)<<"|"<<qtype.getName()<<"|"<<escape(content)<<"|"<<ttl<<"|"<<priority<<"|"<<domain_id
     <<"|"<<last_modified;
  return ostr.str();
}

string DNSResourceRecord::escape(const string &name) const
{
  string a;

  for(string::const_iterator i=name.begin();i!=name.end();++i)
    if(*i=='|' || *i=='\\'){
      a+='\\';
      a+=*i;
    }
    else
      a+=*i;

  return a;
}

int DNSResourceRecord::unSerialize(const string &source)
{
  // qname|qtype|content|ttl|priority|domain_id|last_modified;
  string chunk;
  unsigned int m=0;
  for(int n=0;n<7;++n) {
    chunk="";
    for(;m<source.size();++m) {
      if(source[m]=='\\' && m+1<source.size()) 
	chunk.append(1,source[++m]);
      else if(source[m]=='|') {
	++m;
	break;
      }
      else 
	chunk.append(1,source[m]);
    }
    switch(n) {
    case 0:
      qname=chunk;
      break;
    case 1:
      qtype=chunk;
      break;
    case 2:
      content=chunk;
      break;
    case 3:
      ttl=atoi(chunk.c_str());
      break;
    case 4:
      priority=atoi(chunk.c_str());
      break;
    case 5:
      domain_id=atoi(chunk.c_str());
      break;
    case 6:
      last_modified=atoi(chunk.c_str());
      break;
    }
  }
  return m;
}

string DNSBackend::getRemote(DNSPacket *p)
{
  return p->getRemote();
}

bool DNSBackend::getRemote(DNSPacket *p, struct sockaddr *sa, Utility::socklen_t *len)
{
  if(p->d_socklen<*len)
    return false;
  *len=p->d_socklen;
  memcpy(sa,&p->remote,*len);
  return true;
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
  string fullname=d_name+"-"+suffix+param;
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
#ifndef WIN32
  DIR *dir=opendir(arg()["module-dir"].c_str());
  if(!dir) {
    L<<Logger::Error<<"Unable to open module directory '"<<arg()["module-dir"]<<"'"<<endl;
    return;
  }
  struct dirent *entry;
  while((entry=readdir(dir))) {
    if(!strncmp(entry->d_name,"lib",3) && 
       entry->d_name[strlen(entry->d_name)-1]=='o' && 
       entry->d_name[strlen(entry->d_name)-2]=='s' &&
       entry->d_name[strlen(entry->d_name)-3]=='.')
      load(entry->d_name);
  }
  closedir(dir);
#endif // WIN32
}

void BackendMakerClass::load(const string &module)
{
  int res;

  if(module.find(".")==string::npos)
    res=UeberBackend::loadmodule(arg()["module-dir"]+"/lib"+module+"backend.so");
  else if(module[0]=='/' || (module[0]=='.' && module[1]=='/') || (module[0]=='.' && module[1]=='.'))    // absolute or current path
    res=UeberBackend::loadmodule(module);
  else
    res=UeberBackend::loadmodule(arg()["module-dir"]+"/"+module);
  
  if(res==false) {
    L<<Logger::Error<<"Unable to load module "<<module<<endl;
    exit(1);
  }
}

void BackendMakerClass::launch(const string &instr)
{
  //    if(instr.empty())
  // throw ArgException("Not launching any backends - nameserver won't function");
  
  vector<string> parts;
  stringtok(parts,instr,", ");
  
  for(vector<string>::const_iterator i=parts.begin();i!=parts.end();++i) {
    const string &part=*i;
    
    string module, name;
    vector<string>pparts;
    stringtok(pparts,part,": ");
    module=pparts[0];
    if(pparts.size()>1)
      name=pparts[1]+"-";
      
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

vector<DNSBackend *>BackendMakerClass::all()
{
  vector<DNSBackend *>ret;
  if(d_instances.empty())
    throw AhuException("No database backends configured for launch, unable to function");

  try {
    for(vector<pair<string,string> >::const_iterator i=d_instances.begin();i!=d_instances.end();++i) {
      DNSBackend *made=d_repository[i->first]->make(i->second);
      if(!made)
	throw AhuException("Unable to launch backend '"+i->first+"'");

      ret.push_back(made);
    }
  }
  catch(...) {
    // and cleanup
    for(vector<DNSBackend *>::const_iterator i=ret.begin();i!=ret.end();++i)
      delete *i;
    throw;
  }
  
  return ret;
}

bool DNSBackend::getSOA(const string &domain, SOAData &sd)
{
  this->lookup(QType(QType::SOA),domain,0);
  
  DNSResourceRecord rr;

  int hits=0;

  while(this->get(rr)) {
    hits++;
    DNSPacket::fillSOAData(rr.content, sd);
    sd.domain_id=rr.domain_id;
    sd.ttl=rr.ttl;
  }
  
  if(!hits)
    return false;

  if(sd.nameserver.empty())
    sd.nameserver=arg()["default-soa-name"];
  
  if(sd.hostmaster.empty())
    sd.hostmaster="hostmaster."+domain;

  if(!sd.serial) { // magic time!
    DLOG(L<<Logger::Warning<<"Doing soa serialnumber autocalculation for "<<rr.qname<<endl);

    // we do this by listing the domain and taking the maximum last modified timestamp

    DNSResourceRecord i;
    time_t newest=0;

    if(!(this->list(sd.domain_id))) 
      throw AhuException("Backend error trying to determine magic serial number of zone '"+domain+"'");
  
    while(this->get(i)) {
      if(i.last_modified>newest)
	newest=i.last_modified;
    }

    sd.serial=newest;
    DLOG(L<<"autocalculated soa serialnumber for "<<rr.qname<<" is "<<newest<<endl);

  }
  sd.db=this;
  return true;
}

