
#include "dolog.hh"
#include "dnsdist.hh"
#include "dnsdist-ecs.hh"
#include "dnsparser.hh"
#include "dnswriter.hh"
#include "ednssubnet.hh"

/* when we add EDNS to a query, we don't want to advertise
   a large buffer size */
size_t q_EdnsUDPPayloadSize = 512;
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

int locateEDNSOptRR(const char * packet, const size_t len, const char ** optStart, size_t * optLen, bool * last)
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
static int getEDNSOptionsStart(char* packet, const size_t offset, const size_t len, char ** optStart, size_t * remaining, uint16_t ** optRDLen)
{
  assert(packet != NULL);
  assert(optStart != NULL);
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

  pos += consumed + DNS_TYPE_SIZE + DNS_CLASS_SIZE;
  if(qtype != QType::OPT || (len - pos) < (DNS_TTL_SIZE + DNS_RDLENGTH_SIZE))
    return ENOENT;

  *optStart = packet + pos;
  *remaining = len - pos;

  if (optRDLen) {
    *optRDLen = (uint16_t *)(packet + pos + DNS_TTL_SIZE);
  }

  return 0;
}

/* extract a specific EDNS0 option from a pointer on the beginning of the OPT RR */
static int getEDNSOption(char* optRR, const size_t len, const uint16_t wantedOption, char ** optionValue, size_t * optionValueSize)
{
  assert(optRR != NULL);
  assert(optionValue != NULL);
  assert(optionValueSize != NULL);
  size_t pos = 0;

  pos += DNS_TTL_SIZE;
  const uint16_t rdLen = ntohs(*((uint16_t*) (optRR + pos)));
  size_t rdPos = 0;
  pos += DNS_RDLENGTH_SIZE;  

  while(pos < (len - ((size_t) EDNS_OPTION_CODE_SIZE + EDNS_OPTION_LENGTH_SIZE)) &&
        rdPos < (rdLen - ((size_t) EDNS_OPTION_CODE_SIZE + EDNS_OPTION_LENGTH_SIZE))) {
    const uint16_t optionCode = ntohs(*((uint16_t*) (optRR + pos)));
    pos += EDNS_OPTION_CODE_SIZE;
    rdPos += EDNS_OPTION_CODE_SIZE;
    const uint16_t optionLen = ntohs(*((uint16_t*) (optRR + pos)));
    pos += EDNS_OPTION_LENGTH_SIZE;
    rdPos += EDNS_OPTION_LENGTH_SIZE;

    if (optionLen > (rdLen - rdPos) || optionLen > (len - pos))
      return EINVAL;
    
    if (optionCode == wantedOption) {
      *optionValue = optRR + pos - (EDNS_OPTION_CODE_SIZE + EDNS_OPTION_LENGTH_SIZE);
      *optionValueSize = optionLen + EDNS_OPTION_CODE_SIZE + EDNS_OPTION_LENGTH_SIZE;
      return 0;
    }
    else {
      /* skip this option */
      pos += optionLen;
      rdPos += optionLen;
    }
  }
  
  return ENOENT;
}

static void generateECSOption(const ComboAddress& source, string& res)
{
  const uint16_t ecsOptionCode = htons(EDNS0_OPTION_CODE_ECS);
  Netmask sourceNetmask(source, source.sin4.sin_family == AF_INET ? g_ECSSourcePrefixV4 : g_ECSSourcePrefixV6);
  EDNSSubnetOpts ecsOpts;
  ecsOpts.source = sourceNetmask;
  string payload = makeEDNSSubnetOptsString(ecsOpts);
  const uint16_t payloadLen = htons(payload.length());
  res.append((const char *) &ecsOptionCode, sizeof ecsOptionCode);
  res.append((const char *) &payloadLen, sizeof payloadLen);
  res.append(payload);
}

static void generateECSOptRR(const ComboAddress& source, string & res)
{
  const uint8_t name = 0;
  dnsrecordheader dh;
  EDNS0Record edns0;
  edns0.extRCode = 0;
  edns0.version = 0;
  edns0.Z = 0;
  
  dh.d_type = htons(QType::OPT);
  dh.d_class = htons(q_EdnsUDPPayloadSize);
  memcpy(&dh.d_ttl, &edns0, sizeof edns0);
  string optRData;
  generateECSOption(source, optRData);
  dh.d_clen = htons((uint16_t) optRData.length());
  res.assign((const char *) &name, sizeof name);
  res.append((const char *) &dh, sizeof dh);
  res.append(optRData.c_str(), optRData.length());
}

static void replaceEDNSClientSubnetOption(char * const packet, const size_t packetSize, uint16_t * const len, string& largerPacket, const ComboAddress& remote, char * const oldEcsOptionStart, size_t const oldEcsOptionSize, uint16_t * const optRDLen)
{
  assert(packet != NULL);
  assert(len != NULL);
  assert(oldEcsOptionStart != NULL);
  assert(optRDLen != NULL);
  string ECSOption;
  generateECSOption(remote, ECSOption);

  if (ECSOption.size() == oldEcsOptionSize) {
    /* same size as the existing option */
    memcpy(oldEcsOptionStart, ECSOption.c_str(), oldEcsOptionSize);
  }
  else {
    /* different size than the existing option */
    const unsigned int newPacketLen = *len + (ECSOption.length() - oldEcsOptionSize);
    const size_t beforeOptionLen = oldEcsOptionStart - packet;
    const size_t dataBehindSize = *len - beforeOptionLen - oldEcsOptionSize;
          
    /* fix the size of ECS Option RDLen */
    uint16_t newRDLen = htons(*optRDLen);
    newRDLen += (ECSOption.size() - oldEcsOptionSize);
    *optRDLen = htons(newRDLen);
    
    if (newPacketLen <= packetSize) {
      /* it fits in the existing buffer */
      if (dataBehindSize > 0) {
        memmove(oldEcsOptionStart, oldEcsOptionStart + oldEcsOptionSize, dataBehindSize);
      }
      memcpy(oldEcsOptionStart + dataBehindSize, ECSOption.c_str(), ECSOption.size());
      *len = newPacketLen;
    }
    else {
      /* We need a larger packet */
      if (newPacketLen > largerPacket.capacity()) {
        largerPacket.reserve(newPacketLen);
      }
      /* copy data before the existing option */
      largerPacket.append(packet, beforeOptionLen);
      /* copy the new option */
      largerPacket.append(ECSOption);
      /* copy data that where behind the existing option */
      if (dataBehindSize > 0) {
        largerPacket.append(oldEcsOptionStart + oldEcsOptionSize, dataBehindSize);
      }
    }
  }
}

void handleEDNSClientSubnet(char * const packet, const size_t packetSize, const unsigned int consumed, uint16_t * const len, string& largerPacket, bool * const ednsAdded, const ComboAddress& remote)
{
  assert(packet != NULL);
  assert(len != NULL);
  assert(*len >= 0);
  assert(consumed <= (size_t) *len);
  assert(ednsAdded != NULL);
  char * optRRStart = NULL;
  uint16_t * optRDLen = NULL;
  size_t remaining = 0;
        
  int res = getEDNSOptionsStart(packet, consumed, *len, &optRRStart, &remaining, &optRDLen);
        
  if (res == 0) {
    char * ecsOptionStart = NULL;
    size_t ecsOptionSize = 0;
    
    res = getEDNSOption(optRRStart, remaining, EDNS0_OPTION_CODE_ECS, &ecsOptionStart, &ecsOptionSize);
    
    if (res == 0) {
      /* there is already an EDNS0_OPTION_CODE_ECS value */
      if (g_ECSOverride) {
        replaceEDNSClientSubnetOption(packet, packetSize, len, largerPacket, remote, ecsOptionStart, ecsOptionSize, optRDLen);
      }
    } else {
      /* we need to add one EDNS0 ECS option, fixing the size of EDNS0 RDLENGTH */
      /* getEDNSOptionsStart has already checked that there is exactly one AR,
         no NS and no AN */
      string ECSOption;
      generateECSOption(remote, ECSOption);
      const size_t ECSOptionSize = ECSOption.size();
      
      uint16_t newRDLen = htons(*optRDLen);
      newRDLen += ECSOptionSize;
      *optRDLen = htons(newRDLen);

      if (packetSize - *len > ECSOptionSize) {
        /* if the existing buffer is large enough */
        memcpy(packet + *len, ECSOption.c_str(), ECSOptionSize);
        *len += ECSOptionSize;
      }
      else {
        if (*len + ECSOptionSize > largerPacket.capacity()) {
          largerPacket.reserve(*len + ECSOptionSize);
        }
        
        largerPacket.append(packet, *len);
        largerPacket.append(ECSOption);
      }
    }
  }
  else {
    /* we need to add a EDNS0 RR with one EDNS0 ECS option, fixing the AR count */
    string EDNSRR;
    struct dnsheader* dh = (struct dnsheader*) packet;
    generateECSOptRR(remote, EDNSRR);
    uint16_t arcount = ntohs(dh->arcount);
    arcount++;
    dh->arcount = htons(arcount);
    *ednsAdded = true;

    /* does it fit in the existing buffer? */
    if (packetSize - *len > EDNSRR.size()) {
      memcpy(packet + *len, EDNSRR.c_str(), EDNSRR.size());
      *len += EDNSRR.size();
    }
    else {
      if (*len + EDNSRR.size() > largerPacket.capacity()) {
        largerPacket.reserve(*len + EDNSRR.size());
      }
      
      largerPacket.append(packet, *len);
      largerPacket.append(EDNSRR);
    }
  }
}
