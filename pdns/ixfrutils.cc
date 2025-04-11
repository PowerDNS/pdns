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

#include <cinttypes>
#include <dirent.h>
#include <cerrno>
#include <sys/stat.h>

#include "ixfrutils.hh"
#include "sstuff.hh"
#include "dnssecinfra.hh"
#include "zoneparser-tng.hh"
#include "dnsparser.hh"

uint32_t getSerialFromPrimary(const ComboAddress& primary, const ZoneName& zone, shared_ptr<const SOARecordContent>& soarecord, const TSIGTriplet& tsig, const uint16_t timeout)
{
  vector<uint8_t> packet;
  DNSPacketWriter pw(packet, zone, QType::SOA);
  if(!tsig.algo.empty()) {
    TSIGRecordContent trc;
    trc.d_algoName = tsig.algo;
    trc.d_time = time(nullptr);
    trc.d_fudge = 300;
    trc.d_origID=ntohs(pw.getHeader()->id);
    trc.d_eRcode=0;
    addTSIG(pw, trc, tsig.name, tsig.secret, "", false);
  }

  Socket s(primary.sin4.sin_family, SOCK_DGRAM);
  s.connect(primary);
  string msg((const char*)&packet[0], packet.size());
  s.writen(msg);

  string reply;
  reply.resize(4096);
  // will throw a NetworkError on timeout
  size_t got = s.readWithTimeout(reply.data(), reply.size(), timeout);
  if (got < sizeof(dnsheader)) {
    throw std::runtime_error("Invalid response size " + std::to_string(got));
  }

  reply.resize(got);

  MOADNSParser mdp(false, reply);
  if(mdp.d_header.rcode) {
    throw std::runtime_error("RCODE from response is not NoError but " + RCode::to_s(mdp.d_header.rcode));
  }
  for(const auto& r: mdp.d_answers) {
    if(r.d_type == QType::SOA) {
      soarecord = getRR<SOARecordContent>(r);
      if(soarecord != nullptr) {
        return soarecord->d_st.serial;
      }
    }
  }
  return 0;
}

uint32_t getSerialFromDir(const std::string& dir)
{
  uint32_t ret = 0;
  auto directoryError = pdns::visit_directory(dir, [&ret]([[maybe_unused]] ino_t inodeNumber, const std::string_view& name) {
    try {
      auto version = pdns::checked_stoi<uint32_t>(std::string(name));
      if (std::to_string(version) == name) {
        ret = std::max(version, ret);
      }
    }
    catch (...) {
    }
    return true;
  });

  if (directoryError) {
    throw runtime_error("Could not open IXFR directory '" + dir + "': " + *directoryError);
  }

  return ret;
}

uint32_t getSerialFromRecords(const records_t& records, DNSRecord& soaret)
{
  uint16_t t=QType::SOA;

  auto found = records.equal_range(std::tie(g_rootdnsname, t));

  for(auto iter = found.first; iter != found.second; ++iter) {
    auto soa = getRR<SOARecordContent>(*iter);
    if (soa) {
      soaret = *iter;
      return soa->d_st.serial;
    }
  }
  return 0;
}

static void writeRecords(FILE* fp, const records_t& records)
{
  for(const auto& r: records) {
    if(fprintf(fp, "%s\t%" PRIu32 "\tIN\t%s\t%s\n",
            r.d_name.isRoot() ? "@" :  r.d_name.toStringNoDot().c_str(),
            r.d_ttl,
            DNSRecordContent::NumberToType(r.d_type).c_str(),
            r.getContent()->getZoneRepresentation().c_str()) < 0) {
      throw runtime_error(stringerror());
    }
  }
}

void writeZoneToDisk(const records_t& records, const ZoneName& zone, const std::string& directory)
{
  DNSRecord soa;
  auto serial = getSerialFromRecords(records, soa);
  string fname = directory + "/" + std::to_string(serial);
  /* ensure that the partial zone file will only be accessible by the current user, not even
     by other users in the same group, and certainly not by other users. */
  umask(S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH);
  auto filePtr = pdns::UniqueFilePtr(fopen((fname+".partial").c_str(), "w"));
  if (!filePtr) {
    throw runtime_error("Unable to open file '"+fname+".partial' for writing: "+stringerror());
  }

  records_t soarecord;
  soarecord.insert(soa);
  if (fprintf(filePtr.get(), "$ORIGIN %s\n", zone.toString().c_str()) < 0) {
    string error = "Error writing to zone file for " + zone.toLogString() + " in file " + fname + ".partial" + ": " + stringerror();
    filePtr.reset();
    unlink((fname+".partial").c_str());
    throw std::runtime_error(error);
  }

  try {
    writeRecords(filePtr.get(), soarecord);
    writeRecords(filePtr.get(), records);
    writeRecords(filePtr.get(), soarecord);
  } catch (runtime_error &e) {
    filePtr.reset();
    unlink((fname+".partial").c_str());
    throw runtime_error("Error closing zone file for " + zone.toLogString() + " in file " + fname + ".partial" + ": " + e.what());
  }

  if (fclose(filePtr.release()) != 0) {
    string error = "Error closing zone file for " + zone.toLogString() + " in file " + fname + ".partial" + ": " + stringerror();
    unlink((fname+".partial").c_str());
    throw std::runtime_error(error);
  }

  if (rename( (fname+".partial").c_str(), fname.c_str()) != 0) {
    throw std::runtime_error("Unable to move the zone file for " + zone.toLogString() + " from " + fname + ".partial to " + fname + ": " + stringerror());
  }
}

void loadZoneFromDisk(records_t& records, const string& fname, const ZoneName& zone)
{
  ZoneParserTNG zpt(fname, zone);

  zpt.disableGenerate();
  DNSResourceRecord rr;
  bool seenSOA=false;
  while(zpt.get(rr)) {
    if(rr.qtype.getCode() == QType::CNAME && rr.content.empty())
      rr.content=".";
    rr.qname = rr.qname.makeRelative(zone);

    if(rr.qtype.getCode() != QType::SOA || seenSOA==false)
      records.insert(DNSRecord(rr));
    if(rr.qtype.getCode() == QType::SOA) {
      seenSOA=true;
    }
  }
  if(!(rr.qtype.getCode() == QType::SOA && seenSOA)) {
    records.clear();
    throw runtime_error("Zone not complete!");
  }
}

/*
 * Load the zone `zone` from `fname` and put the first found SOA into `soa`
 * Does NOT check for nullptr
 */
void loadSOAFromDisk(const ZoneName& zone, const string& fname, shared_ptr<const SOARecordContent>& soa, uint32_t& soaTTL)
{
  ZoneParserTNG zpt(fname, zone);
  zpt.disableGenerate();
  DNSResourceRecord rr;

  while(zpt.get(rr)) {
    if (rr.qtype == QType::SOA) {
      soa = getRR<SOARecordContent>(DNSRecord(rr));
      soaTTL = rr.ttl;
      return;
    }
  }
}
