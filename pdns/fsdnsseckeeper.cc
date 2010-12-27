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
#include <boost/assign/std/vector.hpp> // for 'operator+=()'
#include <boost/assign/list_inserter.hpp>
using namespace boost::assign;
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
  push_back(outputs)("Modulus", &d_context.N)("PublicExponent",&d_context.E)
    ("PrivateExponent",&d_context.D)
    ("Prime1",&d_context.P)
    ("Prime2",&d_context.Q)
    ("Exponent1",&d_context.DP)
    ("Exponent2",&d_context.DQ)
    ("Coefficient",&d_context.QP);

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

bool DNSSECKeeper::haveActiveKSKFor(const std::string& zone, DNSSECPrivateKey* dpk)
{
  keyset_t keys = getKeys(zone, true);
  // need to get an *active* one!
  if(dpk && !keys.empty()) {
    *dpk = keys.begin()->first;
  }
  return !keys.empty();
  
  #if 0
  fs::path full_path = fs::system_complete( fs::path(d_dirname + "/" + zone + "/keys/" ) );

  if ( !fs::exists( full_path ) )
    return false;

  fs::directory_iterator end_iter;
  for ( fs::directory_iterator dir_itr( full_path );
	dir_itr != end_iter;
	++dir_itr )
  {
    //    cerr<<"Entry: '"<< dir_itr->leaf() <<"'"<<endl;
    if(ends_with(dir_itr->leaf(),".private")) {
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
  #endif
}

unsigned int DNSSECKeeper::getNextKeyIDFromDir(const std::string& dirname)
{
  fs::path full_path = fs::system_complete( fs::path(dirname));

  if ( !fs::exists( full_path ) )
    unixDie("Unable to get next free key id from '"+dirname+"'");

  fs::directory_iterator end_iter;
  unsigned int maxID=0;
  for ( fs::directory_iterator dir_itr( full_path );
	dir_itr != end_iter;
	++dir_itr )
  {
	  if(ends_with(dir_itr->leaf(),".private")) {
		  maxID = max(maxID, (unsigned int)atoi(dir_itr->leaf().c_str()));
	  }
  }
  return maxID+1;
}

std::string DNSSECKeeper::getKeyFilenameById(const std::string& dirname, unsigned int id)
{
  fs::path full_path = fs::system_complete( fs::path(dirname));

  if ( !fs::exists( full_path ) )
    unixDie("Unable to get free key id from '"+dirname+"'");

  fs::directory_iterator end_iter;
  pair<string, string> parts;
  for ( fs::directory_iterator dir_itr( full_path );
    dir_itr != end_iter;
    ++dir_itr )
  {
    parts = splitField(dir_itr->leaf(), '-');
	  if(atoi(parts.first.c_str()) == (signed int)id) 
      return dirname+"/"+dir_itr->leaf();
  }
  throw runtime_error("Could not get filename for key id '"+lexical_cast<string>(id)+"'");
}


void DNSSECKeeper::addKey(const std::string& name, bool keyOrZone, int algorithm, bool active)
{
  DNSSECPrivateKey dpk;
  dpk.d_key.create(1024); // for testing, 1024

  string isc = dpk.d_key.convertToISC();
  DNSKEYRecordContent drc = dpk.getDNSKEY();
  drc.d_flags = 256; // KSK
  drc.d_algorithm = algorithm; 
  string iscName=d_dirname+"/"+name+"/keys/";
  unsigned int id = getNextKeyIDFromDir(iscName);
  time_t inception=time(0);

  struct tm ts;
  gmtime_r(&inception, &ts);

  iscName += (boost::format("%06d-%04d%02d%02d%02d%02d.%u") % id
	      % (1900+ts.tm_year) % (ts.tm_mon + 1)
	      % ts.tm_mday % ts.tm_hour % ts.tm_min % drc.getTag()).str();

  iscName += keyOrZone ? ".ksk" : ".zsk";
  iscName += active ? ".active" : ".passive";
  
  {  
    ofstream iscFile((iscName+".private").c_str());
    iscFile << isc;
  }

  {  
    ofstream dnskeyFile((iscName+".key").c_str());
    dnskeyFile << toCanonic("", name) << " IN DNSKEY " << drc.getZoneRepresentation()<<endl;
  }

}


static bool keyCompareByKindAndID(const DNSSECKeeper::keyset_t::value_type& a, const DNSSECKeeper::keyset_t::value_type& b)
{
  return make_pair(!a.second.keyOrZone, a.second.id) <
         make_pair(!b.second.keyOrZone, b.second.id);
}

void DNSSECKeeper::removeKey(const std::string& zname, unsigned int id)
{
  string fname = getKeyFilenameById(d_dirname+"/keys/", id);
  if(unlink(fname.c_str()) < 0)
    unixDie("removing key file '"+fname+"'");
}

void DNSSECKeeper::deactivateKey(const std::string& zname, unsigned int id)
{
  string fname = getKeyFilenameById(d_dirname+"/keys/", id);
  string newname = boost::replace_last_copy(fname, ".active", ".passive");
  if(rename(fname.c_str(), newname.c_str()) < 0)
    unixDie("renaming file to deactivate key, from: '"+fname+"' to '"+newname+"'");
}

void DNSSECKeeper::activateKey(const std::string& zname, unsigned int id)
{
  string fname = getKeyFilenameById(d_dirname+"/keys/", id);
  string newname = boost::replace_last_copy(fname, ".passive", ".active");
  if(rename(fname.c_str(), newname.c_str()) < 0)
    unixDie("renaming file to deactivate key, from: '"+fname+"' to '"+newname+"'");
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


DNSSECKeeper::keyset_t DNSSECKeeper::getKeys(const std::string& zone, boost::tribool allOrKeyOrZone)
{
  keyset_t keyset;

  fs::path full_path = fs::system_complete( fs::path(d_dirname + "/" + zone + "/keys/" ) );

  if ( !fs::exists( full_path ) )
    return keyset;

  fs::directory_iterator end_iter;
  for ( fs::directory_iterator dir_itr( full_path );
	dir_itr != end_iter;
	++dir_itr )
  {
    //cerr<<"Entry: '"<< dir_itr->leaf() <<"'"<<endl;
    if(ends_with(dir_itr->leaf(),".private")) {
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
      
      unsigned int id;
      sscanf(dir_itr->leaf().c_str(), "%06u-%04d%02d%02d%02d%02d",
        &id,
        &ts1.tm_year, 
        &ts1.tm_mon, &ts1.tm_mday, &ts1.tm_hour, &ts1.tm_min);
	     
      ts1.tm_year -= 1900;
      ts1.tm_mon--;
      
      KeyMetaData kmd;
      
      kmd.id = id;
      kmd.fname = dir_itr->leaf();
      kmd.active = kmd.fname.find(".active") != string::npos;
      kmd.keyOrZone = kmd.fname.find(".ksk") != string::npos;
      if(boost::indeterminate(allOrKeyOrZone) || allOrKeyOrZone == kmd.keyOrZone)
        keyset.push_back(make_pair(dpk, kmd));
    }
    sort(keyset.begin(), keyset.end(), keyCompareByKindAndID);
  }

  return keyset;
}

DNSKEYRecordContent DNSSECPrivateKey::getDNSKEY()
{
  return makeDNSKEYFromRSAKey(&d_key.getContext(), d_algorithm);
}


void DNSSECKeeper::secureZone(const std::string& name, int algorithm)
{
  mkdir((d_dirname+"/"+name).c_str(), 0700);
  if(mkdir((d_dirname+"/"+name+"/keys").c_str(), 0700) < 0)
    unixDie("Making directory for keys in '"+d_dirname+"'");


  // now add the KSK

  addKey(name, true, algorithm);
#if 0

  DNSSECPrivateKey dpk;
  dpk.d_key.create(2048); // for testing, 1024

  string isc = dpk.d_key.convertToISC();
  DNSKEYRecordContent drc = dpk.getDNSKEY();
  drc.d_flags = 257; // ZSK (?? for a KSK?)
  drc.d_algorithm = algorithm;  
  string iscName=d_dirname+"/"+name+"/keys/";

  time_t now=time(0);
  struct tm ts;
  gmtime_r(&now, &ts);
  unsigned int id=1;
  iscName += (boost::format("%06d-%04d%02d%02d%02d%02d.%u.%s.%s") % id
	      % (1900+ts.tm_year) % (ts.tm_mon + 1)
	      % ts.tm_mday % ts.tm_hour % ts.tm_min % drc.getTag() % "ksk" % "active").str();


  {  
    ofstream iscFile((iscName+".private").c_str());
    iscFile << isc;
  }

  {  
    ofstream dnskeyFile((iscName+".key").c_str());
    dnskeyFile << toCanonic("", name) << " IN DNSKEY " << drc.getZoneRepresentation()<<endl;
  }
#endif
}
 

