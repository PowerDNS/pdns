#include "dnsseckeeper.hh"
#include "dnssecinfra.hh"
#include "statbag.hh"
#include <boost/foreach.hpp>
#include <boost/program_options.hpp>

using namespace boost;
namespace po = boost::program_options;
po::variables_map g_vm;

StatBag S;

string humanTime(time_t t)
{
  char ret[256];
  struct tm tm;
  localtime_r(&t, &tm);
  strftime(ret, sizeof(ret)-1, "%c", &tm);   // %h:%M %Y-%m-%d
  return ret;
}

int main(int argc, char** argv)
{
  po::options_description desc("Allowed options");
  desc.add_options()
    ("help,h", "produce help message")
    ("key-repository,k", po::value<string>()->default_value("./keys"), "Location of keys")
    ("verbose,v", po::value<bool>(), "be verbose")
    ("force", "force an action")
    ("commands", po::value<vector<string> >());

  po::positional_options_description p;
  p.add("commands", -1);
  po::store(po::command_line_parser(argc, argv).options(desc).positional(p).run(), g_vm);
  po::notify(g_vm);

  vector<string> cmds;

  if(g_vm.count("commands")) 
    cmds = g_vm["commands"].as<vector<string> >();

  if(cmds.empty() || g_vm.count("help")) {
    cerr<<"Usage: \npdnssec [options] [show-zone] [sign-zone] [update-zone-keys]\n";
    cerr<<desc<<endl;
    return 0;
  }

  DNSSECKeeper dk(g_vm["key-repository"].as<string>());

  if(cmds[0] == "update-zone-keys") {
    if(cmds.size() != 2) {
      cerr << "Error: "<<cmds[0]<<" takes exactly 1 parameter"<<endl;
      return 0;
    }

    const string& zone=cmds[1];
    DNSSECPrivateKey dpk;
    
    if(!dk.haveKSKFor(zone, &dpk)) {
      cerr << "No KSK for zone '"<<zone<<"', can't update the ZSKs"<<endl;
      return 0;
    }
    DNSSECKeeper::zskset_t zskset=dk.getZSKsFor(zone);

    int inforce=0;
    if(!zskset.empty())  {
      cerr<<"There were ZSKs already for zone '"<<zone<<"': "<<endl;
      
      BOOST_FOREACH(DNSSECKeeper::zskset_t::value_type value, zskset) {
        cerr<<"Tag = "<<value.first.getDNSKEY().getTag()<<"\tActive: "<<value.second<<", "<<value.first.beginValidity<<" - "<<value.first.endValidity<<endl;
        if(value.second) 
          inforce++;
      }
    }
      
    if(inforce == 2) {
      cerr << "Two ZSKs were active already, not generating a third" << endl;
      return 0;
    }
    dk.addZSKFor(zone);
    dk.addZSKFor(zone, true); // 'next'

    zskset = dk.getZSKsFor(zone);
    if(zskset.empty()) {
      cerr<<"This should not happen, still no ZSK!"<<endl;
    }

    cerr<<"There are now "<<zskset.size()<<" ZSKs"<<endl;
    BOOST_FOREACH(DNSSECKeeper::zskset_t::value_type value, zskset) {
      cerr<<"Tag = "<<value.first.getDNSKEY().getTag()<<"\tActive: "<<value.second<<endl;
    }

  }
  else if(cmds[0] == "show-zone") {
    if(cmds.size() != 2) {
      cerr << "Error: "<<cmds[0]<<" takes exactly 1 parameter"<<endl;
      return 0;
    }
    const string& zone=cmds[1];
    DNSSECPrivateKey dpk;
    
    if(!dk.haveKSKFor(zone, &dpk)) {
      cerr << "No KSK for zone '"<<zone<<"'."<<endl;
    }
    else {
      cerr<<"KSK present:"<<endl;
      cerr<<"Tag = "<<dpk.getDNSKEY().getTag()<<endl;
      cerr<<"KSK DNSKEY = "<<zone<<" IN DNSKEY "<< dpk.getDNSKEY().getZoneRepresentation() << endl;
      cerr<<"DS = "<<zone<<" IN DS "<<makeDSFromDNSKey(zone, dpk.getDNSKEY()).getZoneRepresentation() << endl << endl;
    }
    
    
    DNSSECKeeper::zskset_t zskset=dk.getZSKsFor(zone);

    int inforce=0;
    if(zskset.empty())  {
      cerr << "No ZSKs for zone '"<<zone<<"'."<<endl;
    }
    else {  
      cerr << "ZSKs for zone '"<<zone<<"':"<<endl;
      BOOST_FOREACH(DNSSECKeeper::zskset_t::value_type value, zskset) {
        cerr<<"Tag = "<<value.first.getDNSKEY().getTag()<<"\tActive: "<<value.second<<", "<< humanTime(value.first.beginValidity)<<" - "<<humanTime(value.first.endValidity)<<endl;
        if(value.second) 
        inforce++;
      }
    }
  }
  else if(cmds[0] == "sign-zone") {
    if(cmds.size() != 2) {
      cerr << "Error: "<<cmds[0]<<" takes exactly 1 parameter"<<endl;
      return 0;
    }
    const string& zone=cmds[1];
    DNSSECPrivateKey dpk;
    
    if(dk.haveKSKFor(zone, &dpk) && !g_vm.count("force")) {
      cerr << "There is a key already for zone '"<<zone<<"', use --force to overwrite"<<endl;
      return 0;
    }
      
    dk.addZone(zone);

    if(!dk.haveKSKFor(zone, &dpk)) {
      cerr << "This should not happen, still no key!" << endl;
    }
    cerr<<"Created KSK with tag "<<dpk.getDNSKEY().getTag()<<endl;
  
    DNSSECKeeper::zskset_t zskset=dk.getZSKsFor(zone);

    if(!zskset.empty() && !g_vm.count("force"))  {
      cerr<<"There were ZSKs already for zone '"<<zone<<"'"<<endl;
      return 0;
    }
      
    dk.addZSKFor(zone);
    dk.addZSKFor(zone, true); // 'next'

    zskset = dk.getZSKsFor(zone);
    if(zskset.empty()) {
      cerr<<"This should not happen, still no ZSK!"<<endl;
    }

    cerr<<"There are now "<<zskset.size()<<" ZSKs"<<endl;
    BOOST_FOREACH(DNSSECKeeper::zskset_t::value_type value, zskset) {
      cerr<<"Tag = "<<value.first.getDNSKEY().getTag()<<"\tActive: "<<value.second<<endl;
    }
  }
  else {
    cerr<<"Unknown command '"<<cmds[0]<<"'\n";
    return 1;
  }
  return 0;
}
