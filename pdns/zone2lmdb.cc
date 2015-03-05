/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002 - 2014  PowerDNS.COM BV

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

#include <unistd.h>
#include <string>
#include <map>

#include <iostream>
#include <stdio.h>
#include "namespaces.hh"

#include "dns.hh"
#include "arguments.hh"
#include "bindparserclasses.hh"
#include "statbag.hh"
#include "misc.hh"
#include "dnspacket.hh"
#include "zoneparser-tng.hh"
#include "dnsrecords.hh"
#include <boost/algorithm/string.hpp>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <boost/foreach.hpp>
#include <lmdb.h>
#include "base32.hh"

StatBag S;
int g_numZones=0;
int g_numRecords=0;
int g_numRefs=0;

MDB_env *env;
MDB_dbi data_db, zone_db, data_extended_db, rrsig_db, nsecx_db;
MDB_txn *txn, *txn_zone;

void openDB(){
  mdb_env_create(&env);
  mdb_env_set_mapsize(env, 1*1024*1024*1024);
  mdb_env_set_maxdbs(env, 5);
  mdb_env_open(env, "./", 0, 0644);

  mdb_txn_begin(env, NULL, 0, &txn);

  mdb_dbi_open(txn, "zone", MDB_CREATE, &zone_db);
  mdb_dbi_open(txn, "data", MDB_CREATE | MDB_DUPSORT, &data_db);
  mdb_dbi_open(txn, "extended_data", MDB_CREATE, &data_extended_db);
  mdb_dbi_open(txn, "rrsig", MDB_CREATE | MDB_DUPSORT, &rrsig_db);
  mdb_dbi_open(txn, "nsecx", MDB_CREATE, &nsecx_db);
}

void closeDB(){
  mdb_txn_commit(txn);
  mdb_dbi_close(env, data_db);
  mdb_dbi_close(env, zone_db);
  mdb_dbi_close(env, data_extended_db);
  mdb_dbi_close(env, rrsig_db);
  mdb_dbi_close(env, nsecx_db);
  mdb_env_close(env);
}

string reverse(const string &name) {
  return string(name.rbegin(), name.rend());
}

void emitData(string zone, ZoneParserTNG &zpt){

  bool hasSOA=false, isPresigned=false;
  int numRefs=g_numRefs;
  int numRecords=g_numRecords;
  string metaData="1", qname;
  SOAData sd;
  DNSResourceRecord rr;
  MDB_val key, data, keyExt, dataExt;

  zone=toLower(zone);
  mdb_txn_begin(env, txn, 0, &txn_zone);
  while(zpt.get(rr)) {
    numRecords++;
    qname=toLower(stripDot(rr.qname));
    if (rr.qtype == QType::SOA) {
      hasSOA=true;
      fillSOAData(rr.content, sd);
      sd.ttl=rr.ttl;
      continue;
    }
    if (rr.qtype == QType::NSEC3PARAM) {
      metaData=rr.content;
      continue;
    }

    string keyStr, dataStr;

    if (rr.qtype == QType::RRSIG) {
      isPresigned=true;
      RRSIGRecordContent rrc(rr.content);
      keyStr=zone+"\t"+makeRelative(qname, zone)+"\t"+DNSRecordContent::NumberToType(rrc.d_type);
      dataStr=itoa(rr.ttl)+"\t"+rr.content;

      key.mv_data = (char*)keyStr.c_str();
      key.mv_size = keyStr.length();
      data.mv_data = (char*)dataStr.c_str();
      data.mv_size = dataStr.length();

      mdb_put(txn_zone, rrsig_db, &key, &data, 0);
      continue;
    }

    if (rr.qtype == QType::NSEC || rr.qtype == QType::NSEC3) {
      if (rr.qtype == QType::NSEC)
        keyStr=itoa(g_numZones+1)+"\t"+bitFlip(labelReverse(makeRelative(qname,zone)))+"\xff";
      else
        keyStr=itoa(g_numZones+1)+"\t"+toBase32Hex(bitFlip(fromBase32Hex(makeRelative(qname, zone))));
      dataStr=qname+"\t"+itoa(rr.ttl)+"\t"+rr.qtype.getName()+"\t"+rr.content;

      key.mv_data = (char*)keyStr.c_str();
      key.mv_size = keyStr.length();
      data.mv_data = (char*)dataStr.c_str();
      data.mv_size = dataStr.length();

      mdb_put(txn_zone, nsecx_db, &key, &data, 0);
      continue;
    }

    keyStr=reverse(qname)+"\t"+rr.qtype.getName();
    dataStr=itoa(g_numZones+1)+"\t"+itoa(rr.ttl)+"\t"+rr.content;

    key.mv_data = (char*)keyStr.c_str();
    key.mv_size = keyStr.length();
    data.mv_data = (char*)dataStr.c_str();
    data.mv_size = dataStr.length();

    if (dataStr.length() > 500) {
      string keyStrExt=itoa(++numRefs);
      string dataStrExt="REF\t"+itoa(numRefs);

      keyExt.mv_data = (char*)keyStrExt.c_str();
      keyExt.mv_size = keyStrExt.length();
      dataExt.mv_data = (char*)dataStrExt.c_str();
      dataExt.mv_size = dataStrExt.length();

      mdb_put(txn_zone, data_extended_db, &keyExt, &data, 0);
      mdb_put(txn_zone, data_db, &key, &dataExt, 0);
    } else
      mdb_put(txn_zone, data_db, &key, &data, 0);
  }
  if (hasSOA) {
    string keyStr=bitFlip(labelReverse(zone))+"\xff";
    string dataStr=itoa(g_numZones+1)+"\t"+itoa(sd.ttl)+"\t"+serializeSOAData(sd);

    if (isPresigned)
      dataStr.append("\t"+metaData);

    key.mv_data = (char*)keyStr.c_str();
    key.mv_size = keyStr.length();
    data.mv_data = (char*)dataStr.c_str();
    data.mv_size = dataStr.length();

    mdb_put(txn_zone, zone_db, &key, &data, 0);
  } else {
    mdb_txn_abort(txn_zone);
    throw PDNSException("Zone'"+zone+"' has no SOA record");
  }
  mdb_txn_commit(txn_zone);
  g_numZones++;
  g_numRecords=numRecords;
  g_numRefs=numRefs;
}

ArgvMap &arg()
{
  static ArgvMap theArg;
  return theArg;
}


int main(int argc, char **argv)
try
{
  reportAllTypes();
#if __GNUC__ >= 3
  std::ios_base::sync_with_stdio(false);
#endif

  ::arg().setSwitch("verbose","Verbose comments on operation")="no";
  ::arg().setSwitch("on-error-resume-next","Continue after errors")="no";
  ::arg().set("zone","Zonefile to parse")="";
  ::arg().set("zone-name","Specify an $ORIGIN in case it is not present")="";
  ::arg().set("named-conf","Bind 8/9 named.conf to parse")="";
  
  ::arg().set("soa-minimum-ttl","Do not change")="0";
  ::arg().set("soa-refresh-default","Do not change")="0";
  ::arg().set("soa-retry-default","Do not change")="0";
  ::arg().set("soa-expire-default","Do not change")="0";

  ::arg().setCmd("help","Provide a helpful message");

  S.declare("logmessages");

  string namedfile="";
  string zonefile="";

  ::arg().parse(argc, argv);

  if(::arg().mustDo("help")) {
    cout<<"syntax:"<<endl<<endl;
    cout<<::arg().helpstring()<<endl;
    exit(0);
  }

  if(argc<2) {
    cerr<<"syntax:"<<endl<<endl;
    cerr<<::arg().helpstring()<<endl;
    exit(1);
  }

  namedfile=::arg()["named-conf"];
  zonefile=::arg()["zone"];

  int count=0;

  openDB();

  if(zonefile.empty()) {
    BindParser BP;
    BP.setVerbose(::arg().mustDo("verbose"));
    BP.parse(namedfile.empty() ? "./named.conf" : namedfile);

    vector<BindDomainInfo> domains=BP.getDomains();
    struct stat st;
    for(vector<BindDomainInfo>::iterator i=domains.begin(); i!=domains.end(); ++i) {
      if(stat(i->filename.c_str(), &st) == 0) {
        i->d_dev = st.st_dev;
        i->d_ino = st.st_ino;
      }
    }

    sort(domains.begin(), domains.end()); // put stuff in inode order

    int numdomains=domains.size();
    int tick=numdomains/100;

    cout <<"[";
    for(vector<BindDomainInfo>::const_iterator i=domains.begin(); i!=domains.end(); ++i) {
      if(i->type!="master" && i->type!="slave") {
        cerr<<" Warning! Skipping '"<<i->type<<"' zone '"<<i->name<<"'"<<endl;
        continue;
      }
      try {
        ZoneParserTNG zpt(i->filename, i->name, BP.getDirectory());
        emitData(i->name, zpt);
      }
      catch(std::exception &ae) {
        if(!::arg().mustDo("on-error-resume-next"))
          throw;
        else
          cerr<<endl<<ae.what()<<endl;
      }
      catch(PDNSException &ae) {
        if(!::arg().mustDo("on-error-resume-next"))
          throw;
        else
          cerr<<ae.reason<<endl;
      }
      if(!tick || !((count++)%tick))
        cerr<<"\r"<<count*100/numdomains<<"% done ("<<i->filename<<")\033\133\113";
    }
    cout << "]\n";
    cerr<<"\r100% done\033\133\113"<<endl;
  }
  else {
    ZoneParserTNG zpt(zonefile, ::arg()["zone-name"]);
    cout << "{\"name\":\"" << ::arg()["zone-name"] << "\",\"records\":";
    emitData(::arg()["zone-name"], zpt);
    cout << "}\n";
  }
  cerr<<g_numZones<<" domains were fully parsed, containing "<<g_numRecords<<" records\n";
  closeDB();
  return 0;

}
catch(PDNSException &ae) {
  cerr<<endl<<"Fatal error: "<<ae.reason<<endl;
  return 1;
}
catch(std::exception &e) {
  cerr<<endl<<"Died because of STL error: "<<e.what()<<endl;
  return 1;
}
catch(...) {
  cerr<<endl<<"Died because of unknown exception"<<endl;
  return 1;
}
