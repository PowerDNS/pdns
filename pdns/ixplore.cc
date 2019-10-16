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
#include "arguments.hh"
#include "base64.hh"

#include "misc.hh"
#include "dnsrecords.hh"
#include "statbag.hh"
#include "base32.hh"
#include "dnssecinfra.hh"

#include "dns_random.hh"
#include "gss_context.hh"
#include <boost/multi_index_container.hpp>
#include "resolver.hh"
#include <fstream>
#include "ixfr.hh"
#include "ixfrutils.hh"
StatBag S;

ArgvMap &arg()
{
  static ArgvMap theArg;
  return theArg;
}

void usage() {
  cerr<<"Syntax: ixplore diff ZONE BEFORE_FILE AFTER_FILE"<<endl;
  cerr<<"Syntax: ixplore track IP-ADDRESS PORT ZONE DIRECTORY [TSIGKEY TSIGALGO TSIGSECRET]"<<endl;
}

int main(int argc, char** argv) {
  try {
    for(int n=1 ; n < argc; ++n) {
      if ((string) argv[n] == "--help") {
        usage();
        return EXIT_SUCCESS;
      }

      if ((string) argv[n] == "--version") {
        cerr<<"ixplore "<<VERSION<<endl;
        return EXIT_SUCCESS;
      }
    }

    reportAllTypes();
    string command;
    if(argc < 5 || (command=argv[1], (command!="diff" && command !="track"))) {
      usage();
      exit(EXIT_FAILURE);
    }
    if(command=="diff") {
      records_t before, after;
      DNSName zone(argv[2]);
      cout<<"Loading before from "<<argv[3]<<endl;
      loadZoneFromDisk(before, argv[3], zone);
      cout<<"Parsed "<<before.size()<<" records"<<endl;
      cout<<"Zone was complete (SOA at end)"<<endl;
      cout<<"Loading after from "<<argv[4]<<endl;
      loadZoneFromDisk(after, argv[4], zone);
      cout<<"Parsed "<<after.size()<<" records"<<endl;
      cout<<"Zone was complete (SOA at end)"<<endl;

      vector<DNSRecord> diff;

      set_difference(before.cbegin(), before.cend(), after.cbegin(), after.cend(), back_inserter(diff), before.value_comp());
      for(const auto& d : diff) {
        cout<<'-'<< (d.d_name+zone) <<" IN "<<DNSRecordContent::NumberToType(d.d_type)<<" "<<d.d_content->getZoneRepresentation()<<endl;
      }
      diff.clear();
      set_difference(after.cbegin(), after.cend(), before.cbegin(), before.cend(), back_inserter(diff), before.value_comp());
      for(const auto& d : diff) {
        cout<<'+'<< (d.d_name+zone) <<" IN "<<DNSRecordContent::NumberToType(d.d_type)<<" "<<d.d_content->getZoneRepresentation()<<endl;
      }
      exit(1);
    }

    // must be "track" then

    /* goal in life:
       in directory/zone-name we leave files with their name the serial number
       at startup, retrieve current SOA SERIAL for domain from master server

       compare with what the best is we have in our directory, IXFR from that.
       Store result in memory, read that best zone in memory, apply deltas, write it out.

       Next up, loop this every REFRESH seconds */

    DNSName zone(argv[4]);
    ComboAddress master(argv[2], atoi(argv[3]));
    string directory(argv[5]);
    records_t records;

    uint32_t ourSerial = getSerialFromDir(directory);

    cout<<"Loading zone, our highest available serial is "<< ourSerial<<endl;

    TSIGTriplet tt;
    if(argc > 6)
      tt.name=DNSName(toLower(argv[6]));
    if(argc > 7)
      tt.algo=DNSName(toLower(argv[7]));

    if(argc > 8) {
      if(B64Decode(argv[8], tt.secret) < 0) {
        cerr<<"Could not decode tsig secret!"<<endl;
        exit(EXIT_FAILURE);
      }
    }

    try {
      if(!ourSerial)
        throw std::runtime_error("There is no local zone available");
      string fname=directory+"/"+std::to_string(ourSerial);
      cout<<"Loading serial number "<<ourSerial<<" from file "<<fname<<endl;
      loadZoneFromDisk(records, fname, zone);
      cout<<"Parsed "<<records.size()<<" records"<<endl;
      cout<<"Zone was complete (SOA at end)"<<endl;
    }
    catch(std::exception& e) {
      cout<<"Could not load zone from disk: "<<e.what()<<endl;
      cout<<"Retrieving latest from master "<<master.toStringWithPort()<<endl;
      ComboAddress local = master.sin4.sin_family == AF_INET ? ComboAddress("0.0.0.0") : ComboAddress("::");
      AXFRRetriever axfr(master, zone, tt, &local);
      unsigned int nrecords=0;
      Resolver::res_t nop;
      vector<DNSRecord> chunk;
      char wheel[]="|/-\\";
      int count=0;
      time_t last=0;
      while(axfr.getChunk(nop, &chunk)) {
        for(auto& dr : chunk) {
          if(dr.d_type == QType::TSIG)
            continue;
          dr.d_name.makeUsRelative(zone);
          records.insert(dr);
          nrecords++;
        }

        if(last != time(0)) {
          cout << '\r' << wheel[count % (sizeof(wheel)-1)] << ' ' <<nrecords;
          count++;
          cout.flush();
          last=time(0);
        }
      }
      cout <<"\rDone, got "<<nrecords<<"                                            "<<endl;
      cout<<"Writing to disk.."<<endl;
      writeZoneToDisk(records, zone, directory);
    }

    for(;;) {
      DNSRecord ourSoa;
      ourSerial = getSerialFromRecords(records, ourSoa);

      cout<<"Checking for update, our serial number is "<<ourSerial<<".. ";
      cout.flush();
      shared_ptr<SOARecordContent> sr;
      uint32_t serial = getSerialFromMaster(master, zone, sr, tt);
      if(ourSerial == serial) {
        cout<<"still up to date, their serial is "<<serial<<", sleeping "<<sr->d_st.refresh<<" seconds"<<endl;
        sleep(sr->d_st.refresh);
        continue;
      }

      cout<<"got new serial: "<<serial<<", initiating IXFR!"<<endl;
      auto deltas = getIXFRDeltas(master, zone, ourSoa, tt);
      cout<<"Got "<<deltas.size()<<" deltas, applying.."<<endl;

      for(const auto& delta : deltas) {

        const auto& remove = delta.first;
        const auto& add = delta.second;

        ourSerial=getSerialFromRecords(records, ourSoa);
        uint32_t newserial=0;
        for(const auto& rr : add) {
          if(rr.d_type == QType::SOA) {
            newserial=std::dynamic_pointer_cast<SOARecordContent>(rr.d_content)->d_st.serial;
          }
        }

        cout<<"This delta ("<<ourSerial<<" - "<<newserial<<") has "<<remove.size()<<" removals, "<<add.size()<<" additions"<<endl;
        ofstream report(directory +"/delta."+std::to_string(ourSerial)+"-"+std::to_string(newserial));
        if(remove.empty()) {
          cout<<"This delta is a whole new zone"<<endl;
          report<<"- everything, whole new zone update follow"<<endl;
          records.clear();
        }

        bool stop=false;

        for(const auto& rr : remove) {
          report<<'-'<< (rr.d_name+zone) <<" IN "<<DNSRecordContent::NumberToType(rr.d_type)<<" "<<rr.d_content->getZoneRepresentation()<<endl;
          auto range = records.equal_range(tie(rr.d_name, rr.d_type, rr.d_class, rr.d_content));
          if(range.first == range.second) {
            cout<<endl<<" !! Could not find record "<<rr.d_name<<" to remove!!"<<endl;
            //	  stop=true;
            report.flush();
          }
          records.erase(range.first, range.second);
        }

        for(const auto& rr : add) {
          report<<'+'<< (rr.d_name+zone) <<" IN "<<DNSRecordContent::NumberToType(rr.d_type)<<" "<<rr.d_content->getZoneRepresentation()<<endl;
          records.insert(rr);
        }
        if(stop) {
          cerr<<"Had error condition, stopping.."<<endl;
          report.flush();
          exit(1);
        }
      }
      cout<<"Writing zone to disk.. "; cout.flush();
      writeZoneToDisk(records, zone, directory);
      cout<<"Done"<<endl;
    }
  }
  catch(PDNSException &e2) {
    cerr<<"Fatal: "<<e2.reason<<endl;
  }
  catch(std::exception &e)
  {
    cerr<<"Fatal: "<<e.what()<<endl;
  }
  catch(...)
  {
    cerr<<"Any other exception"<<endl;
  }
}
