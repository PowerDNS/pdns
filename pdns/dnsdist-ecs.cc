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
#include "dolog.hh"
#include "dnsdist.hh"
#include "dnsdist-ecs.hh"
#include "dnsparser.hh"
#include "dnswriter.hh"
#include "ednsoptions.hh"
#include "ednssubnet.hh"

/* when we add EDNS to a query, we don't want to advertise
   a large buffer size */
size_t g_EdnsUDPPayloadSize = 512;
/* draft-ietf-dnsop-edns-client-subnet-04 "11.1.  Privacy" */
uint16_t g_ECSSourcePrefixV4 = 24;
uint16_t g_ECSSourcePrefixV6 = 56;

bool g_ECSOverride{false};

int rewriteResponseWithoutEDNS(const char * packet, const size_t len, vector<uint8_t>& newContent)
{
  assert(packet != NULL);
  assert(len >= sizeof(dnsheader));
  const struct dnsheader* dh = (const struct dnsheader*) packet;

  if (ntohs(dh->arcount) == 0)
    return ENOENT;

  if (ntohs(dh->qdcount) == 0)
    return ENOENT;
    
  vector<uint8_t> content(len - sizeof(dnsheader));
  copy(packet + sizeof(dnsheader), packet + len, content.begin());
  PacketReader pr(content);
  
  size_t idx = 0;
  DNSName rrname;
  uint16_t qdcount = ntohs(dh->qdcount);
  uint16_t ancount = ntohs(dh->ancount);
  uint16_t nscount = ntohs(dh->nscount);
  uint16_t arcount = ntohs(dh->arcount);
  uint16_t rrtype;
  uint16_t rrclass;
  string blob;
  struct dnsrecordheader ah;

  rrname = pr.getName();
  rrtype = pr.get16BitInt();
  rrclass = pr.get16BitInt();
  
  DNSPacketWriter pw(newContent, rrname, rrtype, rrclass, dh->opcode);
  pw.getHeader()->id=dh->id;
  pw.getHeader()->qr=dh->qr;
  pw.getHeader()->aa=dh->aa;
  pw.getHeader()->tc=dh->tc;
  pw.getHeader()->rd=dh->rd;
  pw.getHeader()->ra=dh->ra;
  pw.getHeader()->ad=dh->ad;
  pw.getHeader()->cd=dh->cd;
  pw.getHeader()->rcode=dh->rcode;
  
  /* consume remaining qd if any */
  if (qdcount > 1) {
    for(idx = 1; idx < qdcount; idx++) {
      rrname = pr.getName();
      rrtype = pr.get16BitInt();
      rrclass = pr.get16BitInt();
      (void) rrtype;
      (void) rrclass;
    }
  }

  /* copy AN and NS */
  for (idx = 0; idx < ancount; idx++) {
    rrname = pr.getName();
    pr.getDnsrecordheader(ah);

    pw.startRecord(rrname, ah.d_type, ah.d_ttl, ah.d_class, DNSResourceRecord::ANSWER, true);
    pr.xfrBlob(blob);
    pw.xfrBlob(blob);
  }

  for (idx = 0; idx < nscount; idx++) {
    rrname = pr.getName();
    pr.getDnsrecordheader(ah);

    pw.startRecord(rrname, ah.d_type, ah.d_ttl, ah.d_class, DNSResourceRecord::AUTHORITY, true);
    pr.xfrBlob(blob);
    pw.xfrBlob(blob);
  }
  /* consume AR, looking for OPT */
  for (idx = 0; idx < arcount; idx++) {
    rrname = pr.getName();
    pr.getDnsrecordheader(ah);

    if (ah.d_type != QType::OPT) {
      pw.startRecord(rrname, ah.d_type, ah.d_ttl, ah.d_class, DNSResourceRecord::ADDITIONAL, true);
      pr.xfrBlob(blob);
      pw.xfrBlob(blob);
    } else {
      pr.d_pos += ah.d_clen;
    }
  }
  pw.commit();

  return 0;
}

int locateEDNSOptRR(char * packet, const size_t len, char ** optStart, size_t * optLen, bool * last)
{
  assert(packet != NULL);
  assert(optStart != NULL);
  assert(optLen != NULL);
  assert(last != NULL);
  const struct dnsheader* dh = (const struct dnsheader*) packet;

  if (ntohs(dh->arcount) == 0)
    return ENOENT;

  vector<uint8_t> content(len - sizeof(dnsheader));
  copy(packet + sizeof(dnsheader), packet + len, content.begin());
  PacketReader pr(content);
  size_t idx = 0;
  DNSName rrname;
  uint16_t qdcount = ntohs(dh->qdcount);
  uint16_t ancount = ntohs(dh->ancount);
  uint16_t nscount = ntohs(dh->nscount);
  uint16_t arcount = ntohs(dh->arcount);
  uint16_t rrtype;
  uint16_t rrclass;
  struct dnsrecordheader ah;

  /* consume qd */
  for(idx = 0; idx < qdcount; idx++) {
    rrname = pr.getName();
    rrtype = pr.get16BitInt();
    rrclass = pr.get16BitInt();
    (void) rrtype;
    (void) rrclass;
  }

  /* consume AN and NS */
  for (idx = 0; idx < ancount + nscount; idx++) {
    rrname = pr.getName();
    pr.getDnsrecordheader(ah);
    pr.d_pos += ah.d_clen;
  }

  /* consume AR, looking for OPT */
  for (idx = 0; idx < arcount; idx++) {
    uint16_t start = pr.d_pos;
    rrname = pr.getName();
    pr.getDnsrecordheader(ah);

    if (ah.d_type == QType::OPT) {
      *optStart = packet + sizeof(dnsheader) + start;
      *optLen = (pr.d_pos - start) + ah.d_clen;

      if ((packet + len) < (*optStart + *optLen)) {
        throw std::range_error("Opt record overflow");
      }

      if (idx == ((size_t) arcount - 1)) {
        *last = true;
      }
      else {
        *last = false;
      }
      return 0;
    }
    pr.d_pos += ah.d_clen;
  }

  return ENOENT;
}

/* extract the start of the OPT RR in a QUERY packet if any */
static int getEDNSOptionsStart(char* packet, const size_t offset, const size_t len, char ** optRDLen, size_t * remaining)
{
  assert(packet != NULL);
  assert(optRDLen != NULL);
  assert(remaining != NULL);
  const struct dnsheader* dh = (const struct dnsheader*) packet;
  
  if (offset >= len)
    return ENOENT;

  if (ntohs(dh->qdcount) != 1 || dh->ancount != 0 || ntohs(dh->arcount) != 1 || dh->nscount != 0)
    return ENOENT;

  size_t pos = sizeof(dnsheader) + offset;
  pos += DNS_TYPE_SIZE + DNS_CLASS_SIZE;

  if (pos >= len)
    return ENOENT;

  uint16_t qtype, qclass;
  unsigned int consumed;
  DNSName aname(packet, len, pos, true, &qtype, &qclass, &consumed);

  if ((len - pos) < (consumed + DNS_TYPE_SIZE + DNS_CLASS_SIZE))
    return ENOENT;

  pos += consumed + DNS_TYPE_SIZE + DNS_CLASS_SIZE;
  if(qtype != QType::OPT || (len - pos) < (DNS_TTL_SIZE + DNS_RDLENGTH_SIZE))
    return ENOENT;

  pos += DNS_TTL_SIZE;
  *optRDLen = packet + pos;
  *remaining = len - pos;

  return 0;
}

static void generateECSOption(const ComboAddress& source, string& res, uint16_t ECSPrefixLength)
{
  Netmask sourceNetmask(source, ECSPrefixLength);
  EDNSSubnetOpts ecsOpts;
  ecsOpts.source = sourceNetmask;
  string payload = makeEDNSSubnetOptsString(ecsOpts);
  generateEDNSOption(EDNSOptionCode::ECS, payload, res);
}

void generateOptRR(const std::string& optRData, string& res)
{
  const uint8_t name = 0;
  dnsrecordheader dh;
  EDNS0Record edns0;
  edns0.extRCode = 0;
  edns0.version = 0;
  edns0.Z = 0;
  
  dh.d_type = htons(QType::OPT);
  dh.d_class = htons(g_EdnsUDPPayloadSize);
  static_assert(sizeof(EDNS0Record) == sizeof(dh.d_ttl), "sizeof(EDNS0Record) must match sizeof(dnsrecordheader.d_ttl)");
  memcpy(&dh.d_ttl, &edns0, sizeof edns0);
  dh.d_clen = htons((uint16_t) optRData.length());
  res.assign((const char *) &name, sizeof name);
  res.append((const char *) &dh, sizeof dh);
  res.append(optRData.c_str(), optRData.length());
}

static bool replaceEDNSClientSubnetOption(char * const packet, const size_t packetSize, uint16_t * const len, const ComboAddress& remote, char * const oldEcsOptionStart, size_t const oldEcsOptionSize, unsigned char * const optRDLen, uint16_t ECSPrefixLength)
{
  assert(packet != NULL);
  assert(len != NULL);
  assert(oldEcsOptionStart != NULL);
  assert(optRDLen != NULL);
  string ECSOption;
  generateECSOption(remote, ECSOption, ECSPrefixLength);

  if (ECSOption.size() == oldEcsOptionSize) {
    /* same size as the existing option */
    memcpy(oldEcsOptionStart, ECSOption.c_str(), oldEcsOptionSize);
  }
  else {
    /* different size than the existing option */
    const unsigned int newPacketLen = *len + (ECSOption.length() - oldEcsOptionSize);
    const size_t beforeOptionLen = oldEcsOptionStart - packet;
    const size_t dataBehindSize = *len - beforeOptionLen - oldEcsOptionSize;

    /* check that it fits in the existing buffer */
    if (newPacketLen > packetSize) {
      return false;
    }

    /* fix the size of ECS Option RDLen */
    uint16_t newRDLen = (optRDLen[0] * 256) + optRDLen[1];
    newRDLen += (ECSOption.size() - oldEcsOptionSize);
    optRDLen[0] = newRDLen / 256;
    optRDLen[1] = newRDLen % 256;

    if (dataBehindSize > 0) {
      memmove(oldEcsOptionStart, oldEcsOptionStart + oldEcsOptionSize, dataBehindSize);
    }
    memcpy(oldEcsOptionStart + dataBehindSize, ECSOption.c_str(), ECSOption.size());
    *len = newPacketLen;
  }

  return true;
}

bool handleEDNSClientSubnet(char* const packet, const size_t packetSize, const unsigned int consumed, uint16_t* const len, bool* const ednsAdded, bool* const ecsAdded, const ComboAddress& remote, bool overrideExisting, uint16_t ecsPrefixLength)
{
  assert(packet != NULL);
  assert(len != NULL);
  assert(consumed <= (size_t) *len);
  assert(ednsAdded != NULL);
  assert(ecsAdded != NULL);
  unsigned char * optRDLen = NULL;
  size_t remaining = 0;

  int res = getEDNSOptionsStart(packet, consumed, *len, (char**) &optRDLen, &remaining);
        
  if (res == 0) {
    char * ecsOptionStart = NULL;
    size_t ecsOptionSize = 0;
    
    res = getEDNSOption((char*)optRDLen, remaining, EDNSOptionCode::ECS, &ecsOptionStart, &ecsOptionSize);
    
    if (res == 0) {
      /* there is already an ECS value */
      if (overrideExisting) {
        return replaceEDNSClientSubnetOption(packet, packetSize, len, remote, ecsOptionStart, ecsOptionSize, optRDLen, ecsPrefixLength);
      }
    } else {
      /* we need to add one EDNS0 ECS option, fixing the size of EDNS0 RDLENGTH */
      /* getEDNSOptionsStart has already checked that there is exactly one AR,
         no NS and no AN */
      string ECSOption;
      generateECSOption(remote, ECSOption, ecsPrefixLength);
      const size_t ECSOptionSize = ECSOption.size();
      
      /* check if the existing buffer is large enough */
      if (packetSize - *len <= ECSOptionSize) {
        return false;
      }

      uint16_t newRDLen = (optRDLen[0] * 256) + optRDLen[1];
      newRDLen += ECSOptionSize;
      optRDLen[0] = newRDLen / 256;
      optRDLen[1] = newRDLen % 256;

      memcpy(packet + *len, ECSOption.c_str(), ECSOptionSize);
      *len += ECSOptionSize;
      *ecsAdded = true;
    }
  }
  else {
    /* we need to add a EDNS0 RR with one EDNS0 ECS option, fixing the AR count */
    string EDNSRR;
    struct dnsheader* dh = (struct dnsheader*) packet;
    string optRData;
    generateECSOption(remote, optRData, ecsPrefixLength);
    generateOptRR(optRData, EDNSRR);

    /* does it fit in the existing buffer? */
    if (packetSize - *len <= EDNSRR.size()) {
      return false;
    }

    uint16_t arcount = ntohs(dh->arcount);
    arcount++;
    dh->arcount = htons(arcount);
    *ednsAdded = true;

    memcpy(packet + *len, EDNSRR.c_str(), EDNSRR.size());
    *len += EDNSRR.size();
  }

  return true;
}

static int removeEDNSOptionFromOptions(unsigned char* optionsStart, const uint16_t optionsLen, const uint16_t optionCodeToRemove, uint16_t* newOptionsLen)
{
  unsigned char* p = optionsStart;
  size_t pos = 0;
  while ((pos + 4) <= optionsLen) {
    unsigned char* optionBegin = p;
    const uint16_t optionCode = 0x100*p[0] + p[1];
    p += sizeof(optionCode);
    pos += sizeof(optionCode);
    const uint16_t optionLen = 0x100*p[0] + p[1];
    p += sizeof(optionLen);
    pos += sizeof(optionLen);
    if ((pos + optionLen) > optionsLen) {
      return EINVAL;
    }
    if (optionCode == optionCodeToRemove) {
      if (pos + optionLen < optionsLen) {
        /* move remaining options over the removed one,
           if any */
        memmove(optionBegin, p + optionLen, optionsLen - (pos + optionLen));
      }
      *newOptionsLen = optionsLen - (sizeof(optionCode) + sizeof(optionLen) + optionLen);
      return 0;
    }
    p += optionLen;
    pos += optionLen;
  }
  return ENOENT;
}

int removeEDNSOptionFromOPT(char* optStart, size_t* optLen, const uint16_t optionCodeToRemove)
{
  /* we need at least:
     root label (1), type (2), class (2), ttl (4) + rdlen (2)*/
  if (*optLen < 11) {
    return EINVAL;
  }
  const unsigned char* end = (const unsigned char*) optStart + *optLen;
  unsigned char* p = (unsigned char*) optStart + 9;
  unsigned char* rdLenPtr = p;
  uint16_t rdLen = (0x100*p[0] + p[1]);
  p += sizeof(rdLen);
  if (p + rdLen != end) {
    return EINVAL;
  }
  uint16_t newRdLen = 0;
  int res = removeEDNSOptionFromOptions(p, rdLen, optionCodeToRemove, &newRdLen);
  if (res != 0) {
    return res;
  }
  *optLen -= (rdLen - newRdLen);
  rdLenPtr[0] = newRdLen / 0x100;
  rdLenPtr[1] = newRdLen % 0x100;
  return 0;
}

int rewriteResponseWithoutEDNSOption(const char * packet, const size_t len, const uint16_t optionCodeToSkip, vector<uint8_t>& newContent)
{
  assert(packet != NULL);
  assert(len >= sizeof(dnsheader));
  const struct dnsheader* dh = (const struct dnsheader*) packet;

  if (ntohs(dh->arcount) == 0)
    return ENOENT;

  if (ntohs(dh->qdcount) == 0)
    return ENOENT;

  vector<uint8_t> content(len - sizeof(dnsheader));
  copy(packet + sizeof(dnsheader), packet + len, content.begin());
  PacketReader pr(content);

  size_t idx = 0;
  DNSName rrname;
  uint16_t qdcount = ntohs(dh->qdcount);
  uint16_t ancount = ntohs(dh->ancount);
  uint16_t nscount = ntohs(dh->nscount);
  uint16_t arcount = ntohs(dh->arcount);
  uint16_t rrtype;
  uint16_t rrclass;
  string blob;
  struct dnsrecordheader ah;

  rrname = pr.getName();
  rrtype = pr.get16BitInt();
  rrclass = pr.get16BitInt();

  DNSPacketWriter pw(newContent, rrname, rrtype, rrclass, dh->opcode);
  pw.getHeader()->id=dh->id;
  pw.getHeader()->qr=dh->qr;
  pw.getHeader()->aa=dh->aa;
  pw.getHeader()->tc=dh->tc;
  pw.getHeader()->rd=dh->rd;
  pw.getHeader()->ra=dh->ra;
  pw.getHeader()->ad=dh->ad;
  pw.getHeader()->cd=dh->cd;
  pw.getHeader()->rcode=dh->rcode;

  /* consume remaining qd if any */
  if (qdcount > 1) {
    for(idx = 1; idx < qdcount; idx++) {
      rrname = pr.getName();
      rrtype = pr.get16BitInt();
      rrclass = pr.get16BitInt();
      (void) rrtype;
      (void) rrclass;
    }
  }

  /* copy AN and NS */
  for (idx = 0; idx < ancount; idx++) {
    rrname = pr.getName();
    pr.getDnsrecordheader(ah);

    pw.startRecord(rrname, ah.d_type, ah.d_ttl, ah.d_class, DNSResourceRecord::ANSWER, true);
    pr.xfrBlob(blob);
    pw.xfrBlob(blob);
  }

  for (idx = 0; idx < nscount; idx++) {
    rrname = pr.getName();
    pr.getDnsrecordheader(ah);

    pw.startRecord(rrname, ah.d_type, ah.d_ttl, ah.d_class, DNSResourceRecord::AUTHORITY, true);
    pr.xfrBlob(blob);
    pw.xfrBlob(blob);
  }

  /* consume AR, looking for OPT */
  for (idx = 0; idx < arcount; idx++) {
    rrname = pr.getName();
    pr.getDnsrecordheader(ah);

    if (ah.d_type != QType::OPT) {
      pw.startRecord(rrname, ah.d_type, ah.d_ttl, ah.d_class, DNSResourceRecord::ADDITIONAL, true);
      pr.xfrBlob(blob);
      pw.xfrBlob(blob);
    } else {
      pw.startRecord(rrname, ah.d_type, ah.d_ttl, ah.d_class, DNSResourceRecord::ADDITIONAL, false);
      pr.xfrBlob(blob);
      uint16_t rdLen = blob.length();
      removeEDNSOptionFromOptions((unsigned char*)blob.c_str(), rdLen, optionCodeToSkip, &rdLen);
      /* xfrBlob(string, size) completely ignores size.. */
      if (rdLen > 0) {
        blob.resize((size_t)rdLen);
        pw.xfrBlob(blob);
      } else {
        pw.commit();
      }
    }
  }
  pw.commit();

  return 0;
}
