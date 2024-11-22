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

vector<pair<vector<DNSRecord>, vector<DNSRecord> > > processIXFRRecords(const ComboAddress& primary, const DNSName& zone,
                                                                        const vector<DNSRecord>& records, const std::shared_ptr<const SOARecordContent>& primarySOA)
{
  vector<pair<vector<DNSRecord>, vector<DNSRecord> > >  ret;

  if (records.size() == 0 || primarySOA == nullptr) {
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
      throw std::runtime_error("Error getting the content of the first SOA record of this IXFR sequence for zone '"+zone.toLogString()+"' from primary '"+primary.toStringWithPort()+"'");
    }

    // cerr<<"Serial is "<<sr->d_st.serial<<", final serial is "<<primarySOA->d_st.serial<<endl;

    // the serial of this SOA record is the serial of the
    // zone before the removals and updates of this sequence
    if (sr->d_st.serial == primarySOA->d_st.serial) {
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
      throw std::runtime_error("No SOA record to finish the removals part of the IXFR sequence of zone '" + zone.toLogString() + "' from " + primary.toStringWithPort());
    }

    sr = getRR<SOARecordContent>(records[pos]);
    if (!sr) {
      throw std::runtime_error("Invalid SOA record to finish the removals part of the IXFR sequence of zone '" + zone.toLogString() + "' from " + primary.toStringWithPort());
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
      throw std::runtime_error("No SOA record to finish the additions part of the IXFR sequence of zone '" + zone.toLogString() + "' from " + primary.toStringWithPort());
    }

    sr = getRR<SOARecordContent>(records[pos]);
    if (!sr) {
      throw std::runtime_error("Invalid SOA record to finish the additions part of the IXFR sequence of zone '" + zone.toLogString() + "' from " + primary.toStringWithPort());
    }

    if (sr->d_st.serial != newSerial) {
      throw std::runtime_error("Invalid serial (" + std::to_string(sr->d_st.serial) + ", expecting " + std::to_string(newSerial) + ") in the SOA record finishing the additions part of the IXFR sequence of zone '" + zone.toLogString() + "' from " + primary.toStringWithPort());
    }

    if (newSerial == primarySOA->d_st.serial) {
      // this was the last sequence
      if (pos != (records.size() - 1)) {
        throw std::runtime_error("Trailing records after the last IXFR sequence of zone '" + zone.toLogString() + "' from " + primary.toStringWithPort());
      }
    }

    ret.emplace_back(remove, add);
  }

  return ret;
}

// Returns pairs of "remove & add" vectors. If you get an empty remove, it means you got an AXFR!
 // NOLINTNEXTLINE(readability-function-cognitive-complexity): https://github.com/PowerDNS/pdns/issues/12791
vector<pair<vector<DNSRecord>, vector<DNSRecord>>> getIXFRDeltas(const ComboAddress& primary, const DNSName& zone, const DNSRecord& oursr,
                                                                 uint16_t xfrTimeout, bool totalTimeout,
                                                                 const TSIGTriplet& tt, const ComboAddress* laddr, size_t maxReceivedBytes)
{
  // Auth documents xfrTimeout to be a max idle time (sets totalTimeout=false)
  // Rec documents it to be a total XFR time (sets totalTimeout=true)
  //
  vector<pair<vector<DNSRecord>, vector<DNSRecord> > >  ret;
  vector<uint8_t> packet;
  DNSPacketWriter pw(packet, zone, QType::IXFR);
  pw.getHeader()->qr=0;
  pw.getHeader()->rd=0;
  pw.getHeader()->id=dns_random_uint16();
  pw.startRecord(zone, QType::SOA, 0, QClass::IN, DNSResourceRecord::AUTHORITY);
  oursr.getContent()->toPacket(pw);

  pw.commit();
  TSIGRecordContent trc;
  TSIGTCPVerifier tsigVerifier(tt, primary, trc);
  if(!tt.algo.empty()) {
    TSIGHashEnum the;
    getTSIGHashEnum(tt.algo, the);
    try {
      trc.d_algoName = getTSIGAlgoName(the);
    } catch(PDNSException& pe) {
      throw std::runtime_error("TSIG algorithm '"+tt.algo.toLogString()+"' is unknown.");
    }
    trc.d_time = time((time_t*)nullptr);
    trc.d_fudge = 300;
    trc.d_origID=ntohs(pw.getHeader()->id);
    trc.d_eRcode=0;
    addTSIG(pw, trc, tt.name, tt.secret, "", false);
  }
  uint16_t len=htons(packet.size());
  string msg((const char*)&len, 2);
  msg.append((const char*)&packet[0], packet.size());

  Socket s(primary.sin4.sin_family, SOCK_STREAM);
  if (laddr != nullptr) {
    s.bind(*laddr);
  }
  s.setNonBlocking();

  const time_t xfrStart = time(nullptr);

  // Helper function: if we have a total timeout, check it and set elapsed to the total time taken sofar,
  // otherwise set elapsed to 0, making the total time limit ineffective
  const auto timeoutChecker = [=] () -> time_t {
    time_t elapsed = 0;
    if (totalTimeout) {
      elapsed = time(nullptr) - xfrStart;
      if (elapsed >= xfrTimeout) {
        throw std::runtime_error("Reached the maximum elapsed time in an IXFR delta for zone '" + zone.toLogString() + "' from primary " + primary.toStringWithPort());
      }
    }
    return elapsed;
  };

  s.connect(primary, xfrTimeout);

  time_t elapsed = timeoutChecker();
  // coverity[store_truncates_time_t]
  s.writenWithTimeout(msg.data(), msg.size(), xfrTimeout - elapsed);

  // CURRENT PRIMARY SOA
  // REPEAT:
  //   SOA WHERE THIS DELTA STARTS
  //   RECORDS TO REMOVE
  //   SOA WHERE THIS DELTA GOES
  //   RECORDS TO ADD
  // CURRENT PRIMARY SOA
  std::shared_ptr<const SOARecordContent> primarySOA = nullptr;
  vector<DNSRecord> records;
  size_t receivedBytes = 0;
  std::string reply;

  enum transferStyle { Unknown, AXFR, IXFR } style = Unknown;
  const unsigned int expectedSOAForAXFR = 2;
  const unsigned int expectedSOAForIXFR = 3;
  unsigned int primarySOACount = 0;

  std::string state;
  for (;;) {
    // IXFR or AXFR style end reached? We don't want to process trailing data after the closing SOA
    if (style == AXFR && primarySOACount == expectedSOAForAXFR) {
      state = "AXFRdone";
      break;
    }
    if (style == IXFR && primarySOACount == expectedSOAForIXFR) {
      state = "IXFRdone";
      break;
    }

    elapsed = timeoutChecker();
    try {
      const struct timeval remainingTime = { .tv_sec = xfrTimeout - elapsed, .tv_usec = 0 };
      const struct timeval idleTime = remainingTime;
      readn2WithTimeout(s.getHandle(), &len, sizeof(len), idleTime, remainingTime, false);
    }
    catch (const runtime_error& ex) {
      state = ex.what();
      break;
    }

    len = ntohs(len);
    if (len == 0) {
      state = "zeroLen";
      break;
    }
    // Currently no more break statements after this

    if (maxReceivedBytes > 0 && (maxReceivedBytes - receivedBytes) < (size_t) len) {
      throw std::runtime_error("Reached the maximum number of received bytes in an IXFR delta for zone '"+zone.toLogString()+"' from primary "+primary.toStringWithPort());
    }

    reply.resize(len);

    elapsed = timeoutChecker();
    const struct timeval remainingTime = { .tv_sec = xfrTimeout - elapsed, .tv_usec = 0 };
    const struct timeval idleTime = remainingTime;
    readn2WithTimeout(s.getHandle(), reply.data(), len, idleTime, remainingTime, false);
    receivedBytes += len;

    MOADNSParser mdp(false, reply);
    if (mdp.d_header.rcode) {
      throw std::runtime_error("Got an error trying to IXFR zone '"+zone.toLogString()+"' from primary '"+primary.toStringWithPort()+"': "+RCode::to_s(mdp.d_header.rcode));
    }

    if (!tt.algo.empty()) { // TSIG verify message
      tsigVerifier.check(reply, mdp);
    }

    for (auto& r: mdp.d_answers) {
      if(!primarySOA) {
        // we have not seen the first SOA record yet
        if (r.d_type != QType::SOA) {
          throw std::runtime_error("The first record of the IXFR answer for zone '"+zone.toLogString()+"' from primary '"+primary.toStringWithPort()+"' is not a SOA ("+QType(r.d_type).toString()+")");
        }

        auto soaRecord = getRR<SOARecordContent>(r);
        if (!soaRecord) {
          throw std::runtime_error("Error getting the content of the first SOA record of the IXFR answer for zone '"+zone.toLogString()+"' from primary '"+primary.toStringWithPort()+"'");
        }

        if(soaRecord->d_st.serial == getRR<SOARecordContent>(oursr)->d_st.serial) {
          // we are up to date
          return ret;
        }
        if(soaRecord->d_st.serial < getRR<SOARecordContent>(oursr)->d_st.serial) {
          // we have a higher SOA than the auth? Should not happen, but what can we do?
          throw std::runtime_error("Our serial is higher than remote one for zone '" + zone.toLogString() + "' from primary '" + primary.toStringWithPort() + "': ours " + std::to_string(getRR<SOARecordContent>(oursr)->d_st.serial) + " theirs " + std::to_string(soaRecord->d_st.serial));
        }
        primarySOA = std::move(soaRecord);
        ++primarySOACount;
      } else if (r.d_type == QType::SOA) {
        auto soaRecord = getRR<SOARecordContent>(r);
        if (!soaRecord) {
          throw std::runtime_error("Error getting the content of SOA record of IXFR answer for zone '"+zone.toLogString()+"' from primary '"+primary.toStringWithPort()+"'");
        }

        // we hit a marker SOA record
        if (primarySOA->d_st.serial == soaRecord->d_st.serial) {
          ++primarySOACount;
        }
      }
      // When we see the 2nd record, we can decide what the style is
      if (records.size() == 1 && style == Unknown) {
        if (r.d_type != QType::SOA || primarySOACount == expectedSOAForAXFR) {
          // 1. Non-empty AXFR style has a non-SOA record following the first SOA
          // 2. Empty zone AXFR style: start SOA is immediately followed by end marker SOA
          style = AXFR;
        }
        else {
          // IXFR has a 2nd SOA (with different serial) following the first
          style = IXFR;
        }
      }

      if(r.d_place != DNSResourceRecord::ANSWER) {
        if (r.d_type == QType::TSIG) {
          continue;
        }

        if (r.d_type == QType::OPT) {
          continue;
        }

        throw std::runtime_error("Unexpected record (" +QType(r.d_type).toString()+") in non-answer section ("+std::to_string(r.d_place)+") in IXFR response for zone '"+zone.toLogString()+"' from primary '"+primary.toStringWithPort());
      }

      r.d_name.makeUsRelative(zone);
      records.push_back(r);
    }
  }

  switch (style) {
  case IXFR:
    if (primarySOACount != expectedSOAForIXFR) {
      throw std::runtime_error("Incomplete IXFR transfer (primarySOACount=" + std::to_string(primarySOACount) + ") for '" + zone.toLogString() + "' from primary '" + primary.toStringWithPort() + " state=" + state);
    }
    break;
  case AXFR:
    if (primarySOACount != expectedSOAForAXFR){
      throw std::runtime_error("Incomplete AXFR style transfer (primarySOACount=" + std::to_string(primarySOACount) + ")  for '" + zone.toLogString() + "' from primary '" + primary.toStringWithPort() + " state=" + state);
    }
    break;
  case Unknown:
    throw std::runtime_error("Incomplete XFR (primarySOACount=" + std::to_string(primarySOACount) + ") for '" + zone.toLogString() + "' from primary '" + primary.toStringWithPort() + " state=" + state);
    break;
  }

  return processIXFRRecords(primary, zone, records, primarySOA);
}
