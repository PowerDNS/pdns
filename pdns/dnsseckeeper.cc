#include "dnsseckeeper.hh"
#include "dnssecinfra.hh"
#include "statbag.hh"
#include <iostream>
#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>
#include <polarssl/havege.h>
#include <polarssl/base64.h>
#include <boost/foreach.hpp>
#include <sys/stat.h>
#include <sys/types.h>
#include <fstream>
#include <boost/algorithm/string.hpp>
#include <boost/format.hpp>

namespace fs = boost::filesystem;

using namespace std;
using namespace boost;

void RSAContext::create(unsigned int bits)
{
  havege_state hs;
  havege_init( &hs );
  
  rsa_init(&d_context, RSA_PKCS_V15, 0, havege_rand, &hs ); // FIXME this leaks memory
  int ret=rsa_gen_key(&d_context, bits, 65537);
  if(ret < 0) 
    throw runtime_error("Key generation failed");
}

std::string RSAContext::convertToISC()
{
  string ret;
  typedef vector<pair<string, mpi*> > outputs_t;
  outputs_t outputs;

  outputs.push_back(make_pair("Modulus", &d_context.N));
  outputs.push_back(make_pair("PublicExponent",&d_context.E));
  outputs.push_back(make_pair("PrivateExponent",&d_context.D));
  outputs.push_back(make_pair("Prime1",&d_context.P));
  outputs.push_back(make_pair("Prime2",&d_context.Q));
  outputs.push_back(make_pair("Exponent1",&d_context.DP));
  outputs.push_back(make_pair("Exponent2",&d_context.DQ));
  outputs.push_back(make_pair("Coefficient",&d_context.QP));

  ret = "Private-key-format: v1.2\nAlgorithm: 5 (RSASHA1)\n";

  BOOST_FOREACH(outputs_t::value_type value, outputs) {
    ret += value.first;
    ret += ": ";
    unsigned char tmp[mpi_size(value.second)];
    mpi_write_binary(value.second, tmp, sizeof(tmp));
    unsigned char base64tmp[sizeof(tmp)*2];
    int dlen=sizeof(base64tmp);
    base64_encode(base64tmp, &dlen, tmp, sizeof(tmp));
    ret.append((const char*)base64tmp, dlen);
    ret.append(1, '\n');
  }
  return ret;
}

bool DNSSECKeeper::haveKSKFor(const std::string& zone, DNSSECPrivateKey* dpk)
{
  fs::path full_path = fs::system_complete( fs::path(d_dirname + "/" + zone + "/ksks/" ) );

  if ( !fs::exists( full_path ) )
    return false;

  fs::directory_iterator end_iter;
  for ( fs::directory_iterator dir_itr( full_path );
	dir_itr != end_iter;
	++dir_itr )
  {
    //    cerr<<"Entry: '"<< dir_itr->leaf() <<"'"<<endl;
    if(ends_with(dir_itr->leaf(),".isc")) {
      //      cerr<<"Hit!"<<endl;

      if(dpk) {
	getRSAKeyFromISC(&dpk->d_key.getContext(), dir_itr->path().file_string().c_str());
	
	if(getNSEC3PARAM(zone)) {
	  dpk->d_algorithm = 7;
	}
	else {
	  dpk->d_algorithm = 5;
	}

      }
      return true;
    }
  }

  return false;
}

void DNSSECKeeper::addZSKFor(const std::string& name, int algorithm, bool next)
{
  DNSSECPrivateKey dpk;
  dpk.d_key.create(1024); // for testing, 1024

  string isc = dpk.d_key.convertToISC();
  DNSKEYRecordContent drc = dpk.getDNSKEY();
  drc.d_flags = 256; // KSK
  drc.d_algorithm = algorithm; 
  string iscName=d_dirname+"/"+name+"/zsks/";
  time_t inception=getCurrentInception();
  time_t end=inception+14*86400;

  if(next) {
    inception += 14*86400;
    end += 14*86400;
  }

  struct tm ts;
  gmtime_r(&inception, &ts);

  iscName += (boost::format("%04d%02d%02d%02d%02d") 
	      % (1900+ts.tm_year) % (ts.tm_mon + 1)
	      % ts.tm_mday % ts.tm_hour % ts.tm_min).str();

  iscName += "-";

  gmtime_r(&end, &ts);
  iscName += (boost::format("%04d%02d%02d%02d%02d.%u") 
	      % (1900+ts.tm_year) % (ts.tm_mon + 1)
	      % ts.tm_mday % ts.tm_hour % ts.tm_min % drc.getTag()).str();

  {  
    ofstream iscFile((iscName+".isc").c_str());
    iscFile << isc;
  }

  {  
    ofstream dnskeyFile((iscName+".dnskey").c_str());
    dnskeyFile << toCanonic("", name) << " IN DNSKEY " << drc.getZoneRepresentation()<<endl;
  }

}

bool zskSortByDates(const DNSSECKeeper::zskset_t::value_type& a, const DNSSECKeeper::zskset_t::value_type& b)
{
  return 
    tie(a.second.beginValidity, a.second.endValidity) < 
    tie(b.second.beginValidity, b.second.endValidity);
}
void DNSSECKeeper::deleteZSKFor(const std::string& zname, const std::string& fname)
{
  unlink((d_dirname +"/"+ zname +"/zsks/"+fname).c_str());
}

bool DNSSECKeeper::getNSEC3PARAM(const std::string& zname, NSEC3PARAMRecordContent* ns3p)
{
  fs::path full_path = fs::system_complete( fs::path(d_dirname + "/" + zname + "/nsec3param" ) );
  ifstream ifs(full_path.external_directory_string().c_str());
  // cerr<<"called for nsec3param..."<<endl;
  if(!ifs)
    return false;
    
  if(ns3p) {
    string descr;
    getline(ifs, descr);
    NSEC3PARAMRecordContent* tmp=dynamic_cast<NSEC3PARAMRecordContent*>(DNSRecordContent::mastermake(QType::NSEC3PARAM, 1, descr));
    if(!tmp) {
      cerr<<"Could not parse "<< full_path.external_directory_string() <<endl;
      cerr<<"descr: '"<<descr<<"'\n";
    }
    *ns3p = *tmp;
    delete tmp;
    
    cerr<<"hmm salt: "<<makeHexDump(ns3p->d_salt)<<endl;
  }
  return true;
}

void DNSSECKeeper::setNSEC3PARAM(const std::string& zname, const NSEC3PARAMRecordContent* ns3p)
{
  fs::path full_path = fs::system_complete( fs::path(d_dirname + "/" + zname + "/nsec3param" ) );
  if(ns3p) {
    string descr = ns3p->getZoneRepresentation();
    
    
    ofstream of(full_path.external_directory_string().c_str());
    of << descr;
  }
  else {
    unlink(full_path.external_directory_string().c_str());
  }
}


DNSSECKeeper::zskset_t DNSSECKeeper::getZSKsFor(const std::string& zone, bool all)
{
  zskset_t zskset;

  fs::path full_path = fs::system_complete( fs::path(d_dirname + "/" + zone + "/zsks/" ) );

  if ( !fs::exists( full_path ) )
    return zskset;

  fs::directory_iterator end_iter;
  for ( fs::directory_iterator dir_itr( full_path );
	dir_itr != end_iter;
	++dir_itr )
  {
    //    cerr<<"Entry: '"<< dir_itr->leaf() <<"'"<<endl;
    if(ends_with(dir_itr->leaf(),".isc")) {
      //cerr<<"Hit!"<<endl;
      DNSSECPrivateKey dpk;
      getRSAKeyFromISC(&dpk.d_key.getContext(), dir_itr->path().file_string().c_str());

      if(getNSEC3PARAM(zone)) {
        dpk.d_algorithm = 7;
      }
      else {
        dpk.d_algorithm = 5;
      }
      
      struct tm ts1, ts2;
      
      memset(&ts1, 0, sizeof(ts1));
      memset(&ts2, 0, sizeof(ts2));
      
      sscanf(dir_itr->leaf().c_str(), "%04d%02d%02d%02d%02d-%04d%02d%02d%02d%02d",
	     &ts1.tm_year, 
	     &ts1.tm_mon, &ts1.tm_mday, &ts1.tm_hour, &ts1.tm_min,
	     &ts2.tm_year, 
	     &ts2.tm_mon, &ts2.tm_mday, &ts2.tm_hour, &ts2.tm_min);

      ts1.tm_year -= 1900;
      ts2.tm_year -= 1900;

      ts1.tm_mon--;
      ts2.tm_mon--;

      KeyMetaData kmd;
      kmd.beginValidity=timegm(&ts1);
      kmd.endValidity=timegm(&ts2);
      time_t now=time(0);
      kmd.active = now > kmd.beginValidity && now < kmd.endValidity;
      kmd.fname = dir_itr->leaf();
      zskset.push_back(make_pair(dpk, kmd));
    }
    sort(zskset.begin(), zskset.end(), zskSortByDates);
  }

  return zskset;
}

DNSKEYRecordContent DNSSECPrivateKey::getDNSKEY()
{
  return makeDNSKEYFromRSAKey(&d_key.getContext(), d_algorithm);
}


void DNSSECKeeper::secureZone(const std::string& name, int algorithm)
{
  mkdir((d_dirname+"/"+name).c_str(), 0700);
  mkdir((d_dirname+"/"+name+"/ksks").c_str(), 0700);
  if(mkdir((d_dirname+"/"+name+"/zsks").c_str(), 0700) < 0)
    unixDie("Making directory for keys in '"+d_dirname+"'");

  DNSSECPrivateKey dpk;
  dpk.d_key.create(2048); // for testing, 1024

  string isc = dpk.d_key.convertToISC();
  DNSKEYRecordContent drc = dpk.getDNSKEY();
  drc.d_flags = 257; // ZSK
  drc.d_algorithm = algorithm;  
  string iscName=d_dirname+"/"+name+"/ksks/";

  time_t now=time(0);
  struct tm ts;
  gmtime_r(&now, &ts);
  iscName += (boost::format("%04d%02d%02d%02d%02d.%u") 
	      % (1900+ts.tm_year) % (ts.tm_mon + 1)
	      % ts.tm_mday % ts.tm_hour % ts.tm_min % drc.getTag()).str();


  {  
    ofstream iscFile((iscName+".isc").c_str());
    iscFile << isc;
  }

  {  
    ofstream dnskeyFile((iscName+".dnskey").c_str());
    dnskeyFile << toCanonic("", name) << " IN DNSKEY " << drc.getZoneRepresentation()<<endl;
  }

}
 

