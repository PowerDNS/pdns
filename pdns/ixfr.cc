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
#include "ixfr.hh"
#include "sstuff.hh"
#include "dns_random.hh"
#include "dnsrecords.hh"
#include "dnssecinfra.hh"
#include "tsigverifier.hh"

vector<pair<vector<DNSRecord>, vector<DNSRecord> > > processIXFRRecords(const ComboAddress& master, const DNSName& zone,
                                                                        const vector<DNSRecord>& records, const std::shared_ptr<SOARecordContent>& masterSOA)
{
  vector<pair<vector<DNSRecord>, vector<DNSRecord> > >  ret;

  if (records.size() == 0 || masterSOA == nullptr) {
    return ret;
  }

  // we start at 1 to skip the first SOA record
  // we don't increase pos because the final SOA
  // of the previous sequence is also the first SOA
  // of this one
  for(unsigned int pos = 1; pos < records.size(); ) {
    vector<DNSRecord> remove, add;

    // cerr<<"Looking at record in position "<<pos<<" of type "<<QType(records[pos].d_type).getName()<<endl;

    if (records[pos].d_type != QType::SOA) {
      // this is an actual AXFR!
      return {{remove, records}};
    }

    auto sr = getRR<SOARecordContent>(records[pos]);
    if (!sr) {
      throw std::runtime_error("Error getting the content of the first SOA record of this IXFR sequence for zone '"+zone.toLogString()+"' from master '"+master.toStringWithPort()+"'");
    }

    // cerr<<"Serial is "<<sr->d_st.serial<<", final serial is "<<masterSOA->d_st.serial<<endl;

    // the serial of this SOA record is the serial of the
    // zone before the removals and updates of this sequence
    if (sr->d_st.serial == masterSOA->d_st.serial) {
      if (records.size() == 2) {
        // if the entire update is two SOAs records with the same
        // serial, this is actually an empty AXFR!
        return {{remove, records}};
      }

      // if it's the final SOA, there is nothing for us to see
      break;
    }

    remove.push_back(records[pos]); // this adds the SOA

    // process removals
    for(pos++; pos < records.size() && records[pos].d_type != QType::SOA; ++pos) {
      remove.push_back(records[pos]);
    }

    if (pos >= records.size()) {
      throw std::runtime_error("No SOA record to finish the removals part of the IXFR sequence of zone '" + zone.toLogString() + "' from " + master.toStringWithPort());
    }

    sr = getRR<SOARecordContent>(records[pos]);
    if (!sr) {
      throw std::runtime_error("Invalid SOA record to finish the removals part of the IXFR sequence of zone '" + zone.toLogString() + "' from " + master.toStringWithPort());
    }

    // this is the serial of the zone after the removals
    // and updates, but that might not be the final serial
    // because there might be several sequences
    uint32_t newSerial = sr->d_st.serial;
    add.push_back(records[pos]); // this adds the new SOA

    // process additions
    for(pos++; pos < records.size() && records[pos].d_type != QType::SOA; ++pos)  {
      add.push_back(records[pos]);
    }

    if (pos >= records.size()) {
      throw std::runtime_error("No SOA record to finish the additions part of the IXFR sequence of zone '" + zone.toLogString() + "' from " + master.toStringWithPort());
    }

    sr = getRR<SOARecordContent>(records[pos]);
    if (!sr) {
      throw std::runtime_error("Invalid SOA record to finish the additions part of the IXFR sequence of zone '" + zone.toLogString() + "' from " + master.toStringWithPort());
    }

    if (sr->d_st.serial != newSerial) {
      throw std::runtime_error("Invalid serial (" + std::to_string(sr->d_st.serial) + ", expecting " + std::to_string(newSerial) + ") in the SOA record finishing the additions part of the IXFR sequence of zone '" + zone.toLogString() + "' from " + master.toStringWithPort());
    }

    if (newSerial == masterSOA->d_st.serial) {
      // this was the last sequence
      if (pos != (records.size() - 1)) {
        throw std::runtime_error("Trailing records after the last IXFR sequence of zone '" + zone.toLogString() + "' from " + master.toStringWithPort());
      }
    }

    ret.push_back(make_pair(remove,add));
  }

  return ret;
}

// Returns pairs of "remove & add" vectors. If you get an empty remove, it means you got an AXFR!
vector<pair<vector<DNSRecord>, vector<DNSRecord> > > getIXFRDeltas(const ComboAddress& master, const DNSName& zone, const DNSRecord& oursr, 
                                                                   const TSIGTriplet& tt, const ComboAddress* laddr, size_t maxReceivedBytes)
{
  vector<pair<vector<DNSRecord>, vector<DNSRecord> > >  ret;
  vector<uint8_t> packet;
  DNSPacketWriter pw(packet, zone, QType::IXFR);
  pw.getHeader()->qr=0;
  pw.getHeader()->rd=0;
  pw.getHeader()->id=dns_random_uint16();
  pw.startRecord(zone, QType::SOA, 0, QClass::IN, DNSResourceRecord::AUTHORITY);
  oursr.d_content->toPacket(pw);

  pw.commit();
  TSIGRecordContent trc;
  TSIGTCPVerifier tsigVerifier(tt, master, trc);
  if(!tt.algo.empty()) {
    TSIGHashEnum the;
    getTSIGHashEnum(tt.algo, the);
    try {
      trc.d_algoName = getTSIGAlgoName(the);
    } catch(PDNSException& pe) {
      throw std::runtime_error("TSIG algorithm '"+tt.algo.toLogString()+"' is unknown.");
    }
    trc.d_time = time((time_t*)NULL);
    trc.d_fudge = 300;
    trc.d_origID=ntohs(pw.getHeader()->id);
    trc.d_eRcode=0;
    addTSIG(pw, trc, tt.name, tt.secret, "", false);
  }
  uint16_t len=htons(packet.size());
  string msg((const char*)&len, 2);
  msg.append((const char*)&packet[0], packet.size());

  Socket s(master.sin4.sin_family, SOCK_STREAM);
  //  cout<<"going to connect"<<endl;
  if(laddr)
    s.bind(*laddr);
  s.connect(master);
  //  cout<<"Connected"<<endl;
  s.writen(msg);

  // CURRENT MASTER SOA
  // REPEAT:
  //   SOA WHERE THIS DELTA STARTS
  //   RECORDS TO REMOVE
  //   SOA WHERE THIS DELTA GOES
  //   RECORDS TO ADD
  // CURRENT MASTER SOA 
  std::shared_ptr<SOARecordContent> masterSOA = nullptr;
  vector<DNSRecord> records;
  size_t receivedBytes = 0;
  int8_t ixfrInProgress = -2;
  std::string reply;

  for(;;) {
    // IXFR end
    if (ixfrInProgress >= 0)
      break;

    if(s.read((char*)&len, sizeof(len)) != sizeof(len))
      break;

    len=ntohs(len);
    //    cout<<"Got chunk of "<<len<<" bytes"<<endl;
    if(!len)
      break;

    if (maxReceivedBytes > 0 && (maxReceivedBytes - receivedBytes) < (size_t) len)
      throw std::runtime_error("Reached the maximum number of received bytes in an IXFR delta for zone '"+zone.toLogString()+"' from master "+master.toStringWithPort());

    reply.resize(len);
    readn2(s.getHandle(), &reply.at(0), len);
    receivedBytes += len;

    MOADNSParser mdp(false, reply);
    if(mdp.d_header.rcode) 
      throw std::runtime_error("Got an error trying to IXFR zone '"+zone.toLogString()+"' from master '"+master.toStringWithPort()+"': "+RCode::to_s(mdp.d_header.rcode));

    //    cout<<"Got a response, rcode: "<<mdp.d_header.rcode<<", got "<<mdp.d_answers.size()<<" answers"<<endl;

    if(!tt.algo.empty()) { // TSIG verify message
      tsigVerifier.check(reply, mdp);
    }

    for(auto& r: mdp.d_answers) {
      //      cout<<r.first.d_name<< " " <<r.first.d_content->getZoneRepresentation()<<endl;
      if(!masterSOA) {
        // we have not seen the first SOA record yet
        if (r.first.d_type != QType::SOA) {
          throw std::runtime_error("The first record of the IXFR answer for zone '"+zone.toLogString()+"' from master '"+master.toStringWithPort()+"' is not a SOA ("+QType(r.first.d_type).getName()+")");
        }

        auto sr = getRR<SOARecordContent>(r.first);
        if (!sr) {
          throw std::runtime_error("Error getting the content of the first SOA record of the IXFR answer for zone '"+zone.toLogString()+"' from master '"+master.toStringWithPort()+"'");
        }

        if(sr->d_st.serial == std::dynamic_pointer_cast<SOARecordContent>(oursr.d_content)->d_st.serial) {
          // we are up to date
          return ret;
        }
        masterSOA = sr;
      } else if (r.first.d_type == QType::SOA) {
        auto sr = getRR<SOARecordContent>(r.first);
        if (!sr) {
          throw std::runtime_error("Error getting the content of SOA record of IXFR answer for zone '"+zone.toLogString()+"' from master '"+master.toStringWithPort()+"'");
        }

        // we hit the last SOA record
        // IXFR is considered to be done if we hit the last SOA record twice
        if (masterSOA->d_st.serial == sr->d_st.serial) {
          ixfrInProgress++;
        }
      }

      if(r.first.d_place != DNSResourceRecord::ANSWER) {
        if(r.first.d_type == QType::TSIG)
          continue;

        if(r.first.d_type == QType::OPT)
          continue;

        throw std::runtime_error("Unexpected record (" +QType(r.first.d_type).getName()+") in non-answer section ("+std::to_string(r.first.d_place)+")in IXFR response for zone '"+zone.toLogString()+"' from master '"+master.toStringWithPort());
      }

      r.first.d_name.makeUsRelative(zone);
      records.push_back(r.first);
    }
  }

  //  cout<<"Got "<<records.size()<<" records"<<endl;

  return processIXFRRecords(master, zone, records, masterSOA);
}
