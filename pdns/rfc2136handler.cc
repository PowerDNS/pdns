#include "packethandler.hh"
#include "qtype.hh"
#include "dnspacket.hh"
#include "packetcache.hh"
#include "dnsseckeeper.hh"
#include "base64.hh"
#include "base32.hh"
#include "misc.hh"
#include "arguments.hh"
#include "resolver.hh"
#include "dns_random.hh"
#include "backends/gsql/ssql.hh"

extern PacketCache PC;

pthread_mutex_t PacketHandler::s_rfc2136lock=PTHREAD_MUTEX_INITIALIZER;

// Implement section 3.2.1 and 3.2.2 of RFC2136
int PacketHandler::checkUpdatePrerequisites(const DNSRecord *rr, DomainInfo *di) {
  if (rr->d_ttl != 0)
    return RCode::FormErr;

  // 3.2.1 and 3.2.2 check content length.
  if ( (rr->d_class == QClass::NONE || rr->d_class == QClass::ANY) && rr->d_clen != 0)
    return RCode::FormErr;

  string rrLabel = stripDot(rr->d_label);

  bool foundRecord=false;
  DNSResourceRecord rec;
  di->backend->lookup(QType(QType::ANY), rrLabel);
  while(di->backend->get(rec)) {
    if (!rec.qtype.getCode())
      continue;
    if ((rr->d_type != QType::ANY && rec.qtype == rr->d_type) || rr->d_type == QType::ANY)
      foundRecord=true;
  }

  // Section 3.2.1        
  if (rr->d_class == QClass::ANY && !foundRecord) { 
    if (rr->d_type == QType::ANY) 
      return RCode::NXDomain;
    if (rr->d_type != QType::ANY)
      return RCode::NXRRSet;
  } 

  // Section 3.2.2
  if (rr->d_class == QClass::NONE && foundRecord) {
    if (rr->d_type == QType::ANY)
      return RCode::YXDomain;
    if (rr->d_type != QType::ANY)
      return RCode::YXRRSet;
  }

  return RCode::NoError;
}


// Method implements section 3.4.1 of RFC2136
int PacketHandler::checkUpdatePrescan(const DNSRecord *rr) {
  // The RFC stats that d_class != ZCLASS, but we only support the IN class.
  if (rr->d_class != QClass::IN && rr->d_class != QClass::NONE && rr->d_class != QClass::ANY) 
    return RCode::FormErr;

  QType qtype = QType(rr->d_type);

  if (! qtype.isSupportedType())
    return RCode::FormErr;

  if ((rr->d_class == QClass::NONE || rr->d_class == QClass::ANY) && rr->d_ttl != 0)
    return RCode::FormErr;

  if (rr->d_class == QClass::ANY && rr->d_clen != 0)
    return RCode::FormErr;
  
  if (qtype.isMetadataType())
      return RCode::FormErr;

  if (rr->d_class != QClass::ANY && qtype.getCode() == QType::ANY)
    return RCode::FormErr;

  return RCode::NoError;
}


// Implements section 3.4.2 of RFC2136
uint16_t PacketHandler::performUpdate(const string &msgPrefix, const DNSRecord *rr, DomainInfo *di, bool narrow, bool haveNSEC3, const NSEC3PARAMRecordContent *ns3pr, bool *updatedSerial) {
  uint16_t changedRecords = 0;
  DNSResourceRecord rec;
  vector<DNSResourceRecord> rrset, recordsToDelete;
  set<string> delnonterm, insnonterm; // used to (at the end) fix ENT records.

  string rrLabel = stripDot(rr->d_label);
  rrLabel = toLower(rrLabel);
  QType rrType = QType(rr->d_type);

  if (rr->d_class == QClass::IN) { // 3.4.2.2 QClass::IN means insert or update
    DLOG(L<<msgPrefix<<"Add/Update record (QClass == IN) "<<rrLabel<<"|"<<rrType.getName()<<endl);

    bool foundRecord = false;
    di->backend->lookup(rrType, rrLabel);
    while (di->backend->get(rec)) {
        rrset.push_back(rec);
        foundRecord = true;
    }

    
    if (foundRecord) {

      // SOA updates require the serial to be updated.
      if (rrType == QType::SOA) {
        SOAData sdOld, sdUpdate;
        DNSResourceRecord *oldRec = &rrset.front();
        fillSOAData(oldRec->content, sdOld);
        oldRec->setContent(rr->d_content->getZoneRepresentation());
        fillSOAData(oldRec->content, sdUpdate);
        if (rfc1982LessThan(sdOld.serial, sdUpdate.serial)) {
          changedRecords++;
          di->backend->replaceRRSet(di->id, oldRec->qname, oldRec->qtype, rrset);
          *updatedSerial = true;
          L<<Logger::Notice<<msgPrefix<<"Replacing record "<<rrLabel<<"|"<<rrType.getName()<<endl;
        }
        else
          L<<Logger::Notice<<msgPrefix<<"Provided serial ("<<sdUpdate.serial<<") is older than the current serial ("<<sdOld.serial<<"), ignoring SOA update."<<endl;

      // It's not possible to have multiple CNAME's with the same NAME. So we always update.
      } else if (rrType == QType::CNAME) {
        for (vector<DNSResourceRecord>::iterator i = rrset.begin(); i != rrset.end(); i++) {
          i->ttl = rr->d_ttl;
          i->setContent(rr->d_content->getZoneRepresentation());
          changedRecords++;
        }
        di->backend->replaceRRSet(di->id, rrLabel, rrType, rrset);
        L<<Logger::Notice<<msgPrefix<<"Replacing record "<<rrLabel<<"|"<<rrType.getName()<<endl;

      // In any other case, we must check if the TYPE and RDATA match to provide an update (which effectily means a update of TTL)
      } else {
        foundRecord = false;
        for (vector<DNSResourceRecord>::iterator i = rrset.begin(); i != rrset.end(); i++) {
          string content = rr->d_content->getZoneRepresentation();
          if (rrType == i->qtype.getCode() && i->getZoneRepresentation() == content) {
            foundRecord = true;
            i->ttl = rr->d_ttl;
            changedRecords++;
          }
        }
        if (foundRecord) {
          di->backend->replaceRRSet(di->id, rrLabel, rrType, rrset);
          L<<Logger::Notice<<msgPrefix<<"Replacing record "<<rrLabel<<"|"<<rrType.getName()<<endl;
        }
      }
    }

    // If we haven't found a record that matches, we must add it.
    if (! foundRecord) {
      L<<Logger::Notice<<msgPrefix<<"Adding record "<<rrLabel<<"|"<<rrType.getName()<<endl;
      delnonterm.insert(rrLabel); // always remove any ENT's in the place where we're going to add a record.
      DNSResourceRecord newRec(*rr);
      newRec.domain_id = di->id;
      di->backend->feedRecord(newRec);
      changedRecords++;


      // because we added a record, we need to fix DNSSEC data.
      string shorter(rrLabel);
      bool auth=true;

      set<string> insnonterm;
      if (shorter != di->zone && rrType != QType::DS) {
        do {
          if (shorter == di->zone)
            break;

          bool foundShorter = false;
          di->backend->lookup(QType(QType::ANY), shorter);
          while (di->backend->get(rec)) {
            if (rec.qname != rrLabel)
              foundShorter = true;
            if (rec.qtype == QType::NS)
              auth=false;
          }
          if (!foundShorter && shorter != rrLabel && shorter != di->zone)
            insnonterm.insert(shorter);

        } while(chopOff(shorter));
      }

      if(haveNSEC3)
      {
        string hashed;
        if(!narrow) 
          hashed=toLower(toBase32Hex(hashQNameWithSalt(ns3pr->d_iterations, ns3pr->d_salt, rrLabel)));
        
        di->backend->updateDNSSECOrderAndAuthAbsolute(di->id, rrLabel, hashed, auth);
        if(!auth || rrType == QType::DS)
        {
          di->backend->nullifyDNSSECOrderNameAndAuth(di->id, rrLabel, "NS");
          di->backend->nullifyDNSSECOrderNameAndAuth(di->id, rrLabel, "A");
          di->backend->nullifyDNSSECOrderNameAndAuth(di->id, rrLabel, "AAAA");
        }
      }
      else // NSEC
      {
        di->backend->updateDNSSECOrderAndAuth(di->id, di->zone, rrLabel, auth);
        if(!auth || rrType == QType::DS)
        {
          di->backend->nullifyDNSSECOrderNameAndAuth(di->id, rrLabel, "A");
          di->backend->nullifyDNSSECOrderNameAndAuth(di->id, rrLabel, "AAAA");
        }
      }


      // If we insert an NS, all the records below it become non auth - so, we're inserting a delegate.
      // Auth can only be false when the rrLabel is not the zone 
      if (auth == false && rrType == QType::NS) {
        DLOG(L<<msgPrefix<<"Going to fix auth flags below "<<rrLabel<<endl);
        vector<string> qnames;
        di->backend->listSubZone(rrLabel, di->id);
        while(di->backend->get(rec)) {
          if (rec.qtype.getCode() && rec.qtype.getCode() != QType::DS) // Skip ENT and DS records.
            qnames.push_back(rec.qname);
        }
        for(vector<string>::const_iterator qname=qnames.begin(); qname != qnames.end(); ++qname) {
          if(haveNSEC3)  {
            string hashed;
            if(!narrow) 
              hashed=toLower(toBase32Hex(hashQNameWithSalt(ns3pr->d_iterations, ns3pr->d_salt, *qname)));
        
            di->backend->updateDNSSECOrderAndAuthAbsolute(di->id, *qname, hashed, auth);
            di->backend->nullifyDNSSECOrderNameAndAuth(di->id, *qname, "NS");
          }
          else // NSEC
            di->backend->updateDNSSECOrderAndAuth(di->id, di->zone, *qname, auth);

          di->backend->nullifyDNSSECOrderNameAndAuth(di->id, *qname, "AAAA");
          di->backend->nullifyDNSSECOrderNameAndAuth(di->id, *qname, "A");
        }
      }
    }
  } // rr->d_class == QClass::IN

  
  // Delete records - section 3.4.2.3 and 3.4.2.4 with the exception of the 'always leave 1 NS rule' as that's handled by
  // the code that calls this performUpdate().
  if ((rr->d_class == QClass::ANY || rr->d_class == QClass::NONE) && rrType != QType::SOA) { // never delete a SOA.
    DLOG(L<<msgPrefix<<"Deleting records: "<<rrLabel<<"; QClasse:"<<rr->d_class<<"; rrType: "<<rrType.getName()<<endl);
    di->backend->lookup(rrType, rrLabel);
    while(di->backend->get(rec)) {
      if (rr->d_class == QClass::ANY) { // 3.4.2.3
        if (rec.qname == di->zone && (rec.qtype == QType::NS || rec.qtype == QType::SOA)) // Never delete all SOA and NS's
          rrset.push_back(rec);
        else
          recordsToDelete.push_back(rec);
      }
      if (rr->d_class == QClass::NONE) { // 3.4.2.4
        if (rrType == rec.qtype && rec.getZoneRepresentation() == rr->d_content->getZoneRepresentation())
          recordsToDelete.push_back(rec);
        else
          rrset.push_back(rec);
      }

    }
    di->backend->replaceRRSet(di->id, rrLabel, rrType, rrset);
    L<<Logger::Notice<<msgPrefix<<"Deleting record "<<rrLabel<<"|"<<rrType.getName()<<endl;


    if (recordsToDelete.size()) {
      // If we remove an NS which is not at apex of the zone, we need to make everthing below it auth=true as those now are not delegated anymore.
      if (rrType == QType::NS && rrLabel != di->zone) {
        vector<string> changeAuth;
        di->backend->listSubZone(rrLabel, di->id);
        while (di->backend->get(rec)) {
          if (rec.qtype.getCode()) // skip ENT records, they are always false.
            changeAuth.push_back(rec.qname);
        }
        for (vector<string>::const_iterator changeRec=changeAuth.begin(); changeRec!=changeAuth.end(); ++changeRec) {
          if(haveNSEC3)  {
            string hashed;
            if(!narrow) 
              hashed=toLower(toBase32Hex(hashQNameWithSalt(ns3pr->d_iterations, ns3pr->d_salt, *changeRec)));
        
            di->backend->updateDNSSECOrderAndAuthAbsolute(di->id, *changeRec, hashed, true);
          }
          else // NSEC
            di->backend->updateDNSSECOrderAndAuth(di->id, di->zone, *changeRec, true);
        }
      }

      // Fix ENT records.
      // We must check if we have a record below the current level and if we removed the 'last' record
      // on that level. If so, we must insert an ENT record.
      // We take extra care here to not 'include' the record that we just deleted. Some backends will still return it as they only reload on a commit.
      bool foundDeeper = false, foundOther = false;
      di->backend->listSubZone(rrLabel, di->id);
      while (di->backend->get(rec)) {
        if (rec.qname == rrLabel && !count(recordsToDelete.begin(), recordsToDelete.end(), rec))
          foundOther = true;
        if (rec.qname != rrLabel)
          foundDeeper = true;
      }

      if (foundDeeper && !foundOther) {
        insnonterm.insert(rrLabel);
      } else if (!foundOther) {
        // If we didn't have to insert an ENT, we might have deleted a record at very deep level
        // and we must then clean up the ENT's above the deleted record.
        string shorter(rrLabel);
        do {
          bool foundRealRR=false;
          if (shorter == di->zone)
            break;
          // The reason for a listSubZone here is because might go up the tree and find the root ENT of another branch
          // consider these non ENT-records:
          // a.b.c.d.e.test.com
          // a.b.d.e.test.com
          // if we delete a.b.c.d.e.test.com, we go up to d.e.test.com and then find a.b.d.e.test.com
          // At that point we can stop deleting ENT's because the tree is in tact again.
          di->backend->listSubZone(shorter, di->id);
          while (di->backend->get(rec)) {
            if (rec.qtype.getCode())
              foundRealRR=true;
          }
          if (!foundRealRR)
            delnonterm.insert(shorter);
          else
            break; // we found a real record - tree is ok again.
        }while(chopOff(shorter));
      }
    }
  }


  //Insert and delete ENT's
  if (insnonterm.size() > 0 || delnonterm.size() > 0) {
    DLOG(L<<msgPrefix<<"Updating ENT records - "<<insnonterm.size()<<"|"<<delnonterm.size()<<endl);
    di->backend->updateEmptyNonTerminals(di->id, di->zone, insnonterm, delnonterm, false);
    for (set<string>::const_iterator i=insnonterm.begin(); i!=insnonterm.end(); i++) {
      string hashed;
      if(haveNSEC3)
      {
        string hashed;
        if(!narrow) 
          hashed=toLower(toBase32Hex(hashQNameWithSalt(ns3pr->d_iterations, ns3pr->d_salt, *i)));
        di->backend->updateDNSSECOrderAndAuthAbsolute(di->id, *i, hashed, false);
      }
    }
  }

  return recordsToDelete.size() + changedRecords;
}

int PacketHandler::forwardPacket(const string &msgPrefix, DNSPacket *p, DomainInfo *di) {
  vector<string> forward;
  B.getDomainMetadata(p->qdomain, "FORWARD-2136", forward);

  if (forward.size() == 0 && ! ::arg().mustDo("forward-2136")) {
    L<<Logger::Notice<<msgPrefix<<"Not configured to forward to master, returning NotImpl."<<endl;
    return RCode::NotImp;
  }

  for(vector<string>::const_iterator master=di->masters.begin(); master != di->masters.end(); master++) {
    ComboAddress remote;
    try {
      remote = ComboAddress(*master, 53);
    }
    catch (...) {
      L<<Logger::Error<<msgPrefix<<"Failed to parse "<<*master<<" as valid remote."<<endl;
      continue;
    }

    ComboAddress local;
    if(remote.sin4.sin_family == AF_INET)
      local = ComboAddress(::arg()["query-local-address"]);
    else if(!::arg()["query-local-address6"].empty())
      local = ComboAddress(::arg()["query-local-address6"]);
    else
      local = ComboAddress("::");
    int sock = makeQuerySocket(local, false); // create TCP socket. RFC2136 section 6.2 seems to be ok with this.

    if( connect(sock, (struct sockaddr*)&remote, remote.getSocklen()) < 0 ) {
      L<<Logger::Error<<msgPrefix<<"Failed to connect to "<<remote.toStringWithPort()<<": "<<stringerror()<<endl;
      Utility::closesocket(sock);
      continue;
    }

    DNSPacket forwardPacket(*p);
    forwardPacket.setID(dns_random(0xffff));
    forwardPacket.setRemote(&remote);
    uint16_t len=htons(forwardPacket.getString().length());
    string buffer((const char*)&len, 2);
    buffer.append(forwardPacket.getString());
    if(write(sock, buffer.c_str(), buffer.length()) < 0) { 
      L<<Logger::Error<<msgPrefix<<"Unable to forward update message to "<<remote.toStringWithPort()<<", error:"<<stringerror()<<endl;
      continue;
    }

    int res = waitForData(sock, 10, 0);
    if (!res) {
      L<<Logger::Error<<msgPrefix<<"Timeout waiting for reply from master at "<<remote.toStringWithPort()<<endl;
      Utility::closesocket(sock);
      continue;
    }
    if (res < 0) {
      L<<Logger::Error<<msgPrefix<<"Error waiting for answer from master at "<<remote.toStringWithPort()<<", error:"<<stringerror()<<endl;
      Utility::closesocket(sock);
      continue;
    }

    char lenBuf[2];
    int recvRes;
    recvRes = recv(sock, &lenBuf, sizeof(lenBuf), 0);
    if (recvRes < 0) {
      L<<Logger::Error<<msgPrefix<<"Could not receive data (length) from master at "<<remote.toStringWithPort()<<", error:"<<stringerror()<<endl;
      Utility::closesocket(sock);
      continue;
    }
    int packetLen = lenBuf[0]*256+lenBuf[1];


    char buf[packetLen];
    recvRes = recv(sock, &buf, packetLen, 0);
    if (recvRes < 0) {
      L<<Logger::Error<<msgPrefix<<"Could not receive data (dnspacket) from master at "<<remote.toStringWithPort()<<", error:"<<stringerror()<<endl;
      Utility::closesocket(sock);
      continue;
    }
    Utility::closesocket(sock);

    try {
      MOADNSParser mdp(buf, recvRes);
      L<<Logger::Info<<msgPrefix<<"Forward update message to "<<remote.toStringWithPort()<<", result was RCode "<<mdp.d_header.rcode<<endl;
      return mdp.d_header.rcode;
    }
    catch (...) {
      L<<Logger::Error<<msgPrefix<<"Failed to parse response packet from master at "<<remote.toStringWithPort()<<endl;
      continue;
    }
  }
  L<<Logger::Error<<msgPrefix<<"Failed to forward packet to master(s). Returning ServFail."<<endl;
  return RCode::ServFail;

}

int PacketHandler::processUpdate(DNSPacket *p) {
  if (! ::arg().mustDo("experimental-rfc2136"))
    return RCode::Refused;
  
  string msgPrefix="UPDATE (" + itoa(p->d.id) + ") from " + p->getRemote() + " for " + p->qdomain + ": ";
  L<<Logger::Info<<msgPrefix<<"Processing started."<<endl;

  // Check permissions - IP based
  vector<string> allowedRanges;
  B.getDomainMetadata(p->qdomain, "ALLOW-2136-FROM", allowedRanges);
  if (! ::arg()["allow-2136-from"].empty()) 
    stringtok(allowedRanges, ::arg()["allow-2136-from"], ", \t" );

  NetmaskGroup ng;
  for(vector<string>::const_iterator i=allowedRanges.begin(); i != allowedRanges.end(); i++)
    ng.addMask(*i);
    
  if ( ! ng.match(&p->d_remote)) {
    L<<Logger::Error<<msgPrefix<<"Remote not listed in allow-2136-from or domainmetadata. Sending REFUSED"<<endl;
    return RCode::Refused;
  }


  // Check permissions - TSIG based.
  vector<string> tsigKeys;
  B.getDomainMetadata(p->qdomain, "TSIG-ALLOW-2136", tsigKeys);
  if (tsigKeys.size() > 0) {
    bool validKey = false;
    
    TSIGRecordContent trc;
    string inputkey, message;
    if (! p->getTSIGDetails(&trc,  &inputkey, &message)) {
      L<<Logger::Error<<msgPrefix<<"TSIG key required, but packet does not contain key. Sending REFUSED"<<endl;
      return RCode::Refused;
    }

    for(vector<string>::const_iterator key=tsigKeys.begin(); key != tsigKeys.end(); key++) {
      if (inputkey == *key) // because checkForCorrectTSIG has already been performed earlier on, if the names of the ky match with the domain given. THis is valid.
        validKey=true;
    }

    if (!validKey) {
      L<<Logger::Error<<msgPrefix<<"TSIG key ("<<inputkey<<") required, but no matching key found in domainmetadata, tried "<<tsigKeys.size()<<". Sending REFUSED"<<endl;
      return RCode::Refused;
    }
  }

  if (tsigKeys.size() == 0 && p->d_havetsig)
    L<<Logger::Warning<<msgPrefix<<"TSIG is provided, but domain is not secured with TSIG. Processing continues"<<endl;

  // RFC2136 uses the same DNS Header and Message as defined in RFC1035.
  // This means we can use the MOADNSParser to parse the incoming packet. The result is that we have some different 
  // variable names during the use of our MOADNSParser.
  MOADNSParser mdp(p->getString());
  if (mdp.d_header.qdcount != 1) {
    L<<Logger::Warning<<msgPrefix<<"Zone Count is not 1, sending FormErr"<<endl;
    return RCode::FormErr;
  }     

  if (p->qtype.getCode() != QType::SOA) { // RFC2136 2.3 - ZTYPE must be SOA
    L<<Logger::Warning<<msgPrefix<<"Query ZTYPE is not SOA, sending FormErr"<<endl;
    return RCode::FormErr;
  }

  if (p->qclass != QClass::IN) {
    L<<Logger::Warning<<msgPrefix<<"Class is not IN, sending NotAuth"<<endl;
    return RCode::NotAuth;
  }

  DomainInfo di;
  di.backend=0;
  if(!B.getDomainInfo(p->qdomain, di) || !di.backend) {
    L<<Logger::Error<<msgPrefix<<"Can't determine backend for domain '"<<p->qdomain<<"' (or backend does not support RFC2136 operation)"<<endl;
    return RCode::NotAuth;
  }

  if (di.kind == DomainInfo::Slave)
    return forwardPacket(msgPrefix, p, &di);

  // Check if all the records provided are within the zone 
  for(MOADNSParser::answers_t::const_iterator i=mdp.d_answers.begin(); i != mdp.d_answers.end(); ++i) {
    const DNSRecord *rr = &i->first;
    // Skip this check for other field types (like the TSIG -  which is in the additional section)
    // For a TSIG, the label is the dnskey.
    if (! (rr->d_place == DNSRecord::Answer || rr->d_place == DNSRecord::Nameserver)) 
      continue;

    string label = stripDot(rr->d_label);

    if (!endsOn(label, di.zone)) {
      L<<Logger::Error<<msgPrefix<<"Received update/record out of zone, sending NotZone."<<endl;
      return RCode::NotZone;
    }
  }

  Lock l(&s_rfc2136lock);
  L<<Logger::Info<<msgPrefix<<"starting transaction."<<endl;
  if (!di.backend->startTransaction(p->qdomain, -1)) { // Not giving the domain_id means that we do not delete the records.
    L<<Logger::Error<<msgPrefix<<"Backend for domain "<<p->qdomain<<" does not support transaction. Can't do Update packet."<<endl;
    return RCode::NotImp;
  }

  // 3.2.1 and 3.2.2 - Prerequisite check 
  for(MOADNSParser::answers_t::const_iterator i=mdp.d_answers.begin(); i != mdp.d_answers.end(); ++i) {
    const DNSRecord *rr = &i->first;
    if (rr->d_place == DNSRecord::Answer) {
      int res = checkUpdatePrerequisites(rr, &di);
      if (res>0) {
        L<<Logger::Error<<msgPrefix<<"Failed PreRequisites check, returning "<<res<<endl;
        di.backend->abortTransaction();
        return res;
      }
    } 
  }

  // 3.2.3 - Prerequisite check - this is outside of updatePrequisitesCheck because we check an RRSet and not the RR.
  typedef pair<string, QType> rrSetKey_t;
  typedef vector<DNSResourceRecord> rrVector_t;
  typedef std::map<rrSetKey_t, rrVector_t> RRsetMap_t;
  RRsetMap_t preReqRRsets;
  for(MOADNSParser::answers_t::const_iterator i=mdp.d_answers.begin(); i != mdp.d_answers.end(); ++i) {
    const DNSRecord *rr = &i->first;
    if (rr->d_place == DNSRecord::Answer) {
      // Last line of 3.2.3
      if (rr->d_class != QClass::IN && rr->d_class != QClass::NONE && rr->d_class != QClass::ANY) 
        return RCode::FormErr;

      if (rr->d_class == QClass::IN) {
        rrSetKey_t key = make_pair(stripDot(rr->d_label), rr->d_type);
        rrVector_t *vec = &preReqRRsets[key];
        vec->push_back(DNSResourceRecord(*rr));
      }
    }
  }

  if (preReqRRsets.size() > 0) {
    RRsetMap_t zoneRRsets;
    for (RRsetMap_t::iterator preRRSet = preReqRRsets.begin(); preRRSet != preReqRRsets.end(); ++preRRSet) {
      rrSetKey_t rrSet=preRRSet->first;
      rrVector_t *vec = &preRRSet->second;

      DNSResourceRecord rec;
      di.backend->lookup(QType(QType::ANY), rrSet.first);
      uint16_t foundRR=0, matchRR=0;
      while (di.backend->get(rec)) {
        if (rec.qtype == rrSet.second) {
          foundRR++;
          for(rrVector_t::iterator rrItem=vec->begin(); rrItem != vec->end(); ++rrItem) {
            rrItem->ttl = rec.ttl; // The compare one line below also compares TTL, so we make them equal because TTL is not user within prerequisite checks.
            if (*rrItem == rec) 
              matchRR++;
          }
        }
      }
      if (matchRR != foundRR || foundRR != vec->size()) {
        L<<Logger::Error<<msgPrefix<<"Failed PreRequisites check, returning NXRRSet"<<endl;
        di.backend->abortTransaction();
        return RCode::NXRRSet;
      }
    }
  }



  // 3.4 - Prescan & Add/Update/Delete records
  uint16_t changedRecords = 0;
  try {

    // 3.4.1 - Prescan section
    for(MOADNSParser::answers_t::const_iterator i=mdp.d_answers.begin(); i != mdp.d_answers.end(); ++i) {
      const DNSRecord *rr = &i->first;
      if (rr->d_place == DNSRecord::Nameserver) {
        int res = checkUpdatePrescan(rr);
        if (res>0) {
          L<<Logger::Error<<msgPrefix<<"Failed prescan check, returning "<<res<<endl;
          di.backend->abortTransaction();
          return res;
        }
      }
    }

    bool updatedSerial=false;
    NSEC3PARAMRecordContent ns3pr;
    bool narrow; 
    bool haveNSEC3 = d_dk.getNSEC3PARAM(di.zone, &ns3pr, &narrow);

    // We get all the before/after fields before doing anything to the db.
    // We can't do this inside performUpdate() because when we remove a delegate, the before/after result is different to what it should be
    // to purge the cache correctly - One update/delete might cause a before/after to be created which is before/after the original before/after.
    vector< pair<string, string> > beforeAfterSet;
    /*if (!haveNSEC3) {
      for(MOADNSParser::answers_t::const_iterator i=mdp.d_answers.begin(); i != mdp.d_answers.end(); ++i) {
        const DNSRecord *rr = &i->first;
        if (rr->d_place == DNSRecord::Nameserver) {
          string before, after;
          di.backend->getBeforeAndAfterNames(di.id, di.zone, stripDot(rr->d_label), before, after, (rr->d_class != QClass::IN));
          beforeAfterSet.push_back(make_pair(before, after));
        }
      }
    }*/

    // 3.4.2 - Perform the updates.
    // There's a special condition where deleting the last NS record at zone apex is never deleted (3.4.2.4)
    // This means we must do it outside the normal performUpdate() because that focusses only on a seperate RR.
    vector<const DNSRecord *> nsRRtoDelete;
    for(MOADNSParser::answers_t::const_iterator i=mdp.d_answers.begin(); i != mdp.d_answers.end(); ++i) {
      const DNSRecord *rr = &i->first;
      if (rr->d_place == DNSRecord::Nameserver) {
        if (rr->d_class == QClass::NONE  && rr->d_type == QType::NS && stripDot(rr->d_label) == di.zone)
          nsRRtoDelete.push_back(rr);
        else
          changedRecords += performUpdate(msgPrefix, rr, &di, narrow, haveNSEC3, &ns3pr, &updatedSerial);
      }
    }
    if (nsRRtoDelete.size()) {
      vector<DNSResourceRecord> nsRRInZone;
      DNSResourceRecord rec;
      di.backend->lookup(QType(QType::NS), di.zone);
      while (di.backend->get(rec)) {
        nsRRInZone.push_back(rec);
      }
      if (nsRRInZone.size() > nsRRtoDelete.size()) { // only delete if the NS's we delete are less then what we have in the zone (3.4.2.4)
        for (vector<DNSResourceRecord>::iterator inZone=nsRRInZone.begin(); inZone != nsRRInZone.end(); inZone++) {
          for (vector<const DNSRecord *>::iterator rr=nsRRtoDelete.begin(); rr != nsRRtoDelete.end(); rr++) {
            if (inZone->getZoneRepresentation() == (*rr)->d_content->getZoneRepresentation())
              changedRecords += performUpdate(msgPrefix, *rr, &di, narrow, haveNSEC3, &ns3pr, &updatedSerial);
          }
        }
      }
    }

    // Purge the records!
    string zone(di.zone);
    zone.append("$");
    PC.purge(zone);  // For NSEC3, nuke the complete zone.
/*
    if (changedRecords > 0) {
      if (haveNSEC3) {
        string zone(di.zone);
        zone.append("$");
        PC.purge(zone);  // For NSEC3, nuke the complete zone.
      } else {
        //for(vector< pair<string, string> >::const_iterator i=beforeAfterSet.begin(); i != beforeAfterSet.end(); i++)
          //PC.purgeRange(i->first, i->second, di.zone);
      }
    }
*/
    // Section 3.6 - Update the SOA serial - outside of performUpdate because we do a SOA update for the complete update message
    if (changedRecords > 0 && !updatedSerial)
      increaseSerial(msgPrefix, &di, haveNSEC3, narrow, &ns3pr);

  }
  catch (DBException &e) {
    L<<Logger::Error<<msgPrefix<<"Caught DBException: "<<e.reason<<"; Sending ServFail!"<<endl;
    di.backend->abortTransaction();
    return RCode::ServFail;
  }
  catch (AhuException &e) {
    L<<Logger::Error<<msgPrefix<<"Caught AhuException: "<<e.reason<<"; Sending ServFail!"<<endl;
    di.backend->abortTransaction();
    return RCode::ServFail;
  }
  catch (SSqlException &e) {
    L<<Logger::Error<<msgPrefix<<"Caught SSqlException: "<<e.txtReason()<<"; Sending ServFail!"<<endl;
    di.backend->abortTransaction();
    return RCode::ServFail;
  }  
  catch (...) {
    L<<Logger::Error<<msgPrefix<<"Caught unknown exception when performing update. Sending ServFail!"<<endl;
    di.backend->abortTransaction();
    return RCode::ServFail;
  }
  
  if (!di.backend->commitTransaction()) {
    L<<Logger::Error<<msgPrefix<<"Failed to commit update for domain "<<di.zone<<"!"<<endl;
    return RCode::ServFail;
  }
 
  L<<Logger::Info<<msgPrefix<<"Update completed, "<<changedRecords<<" changed records commited."<<endl;
  return RCode::NoError; //rfc 2136 3.4.2.5
}

void PacketHandler::increaseSerial(const string &msgPrefix, const DomainInfo *di, bool haveNSEC3, bool narrow, const NSEC3PARAMRecordContent *ns3pr) {
  DNSResourceRecord rec, newRec;
  di->backend->lookup(QType(QType::SOA), di->zone);
  bool foundSOA=false;
  while (di->backend->get(rec)) {
    newRec = rec;
    foundSOA=true;
  }
  if (!foundSOA) {
    throw AhuException("SOA-Serial update failed because there was no SOA. Wowie.");
  }
  SOAData soa2Update;
  fillSOAData(rec.content, soa2Update);

  vector<string> soaEdit2136Setting;
  B.getDomainMetadata(di->zone, "SOA-EDIT-2136", soaEdit2136Setting);
  string soaEdit2136 = "DEFAULT";
  string soaEdit;
  if (!soaEdit2136Setting.empty()) {
    soaEdit2136 = soaEdit2136Setting[0];
    if (pdns_iequals(soaEdit2136, "SOA-EDIT") || pdns_iequals(soaEdit2136,"SOA-EDIT-INCREASE") ){
      vector<string> soaEditSetting;
      B.getDomainMetadata(di->zone, "SOA-EDIT", soaEditSetting);
      if (soaEditSetting.empty()) {
        L<<Logger::Error<<msgPrefix<<"Using "<<soaEdit2136<<" for SOA-EDIT-2136 increase on RFC2136, but SOA-EDIT is not set for domain. Using DEFAULT for SOA-EDIT-2136"<<endl;
        soaEdit2136 = "DEFAULT";
      } else
        soaEdit = soaEditSetting[0];
    }
  }


  if (pdns_iequals(soaEdit2136, "INCREASE"))
    soa2Update.serial++;
  else if (pdns_iequals(soaEdit2136, "SOA-EDIT-INCREASE")) {
    uint32_t newSer = calculateEditSOA(soa2Update, soaEdit);
    if (newSer <= soa2Update.serial)
      soa2Update.serial++;
    else
      soa2Update.serial = newSer;
  } else if (pdns_iequals(soaEdit2136, "SOA-EDIT"))
    soa2Update.serial = calculateEditSOA(soa2Update, soaEdit);
  else if (pdns_iequals(soaEdit2136, "EPOCH"))
    soa2Update.serial = time(0);
  else {
    time_t now = time(0);
    struct tm tm;
    localtime_r(&now, &tm);
    boost::format fmt("%04d%02d%02d%02d");
    string newserdate=(fmt % (tm.tm_year+1900) % (tm.tm_mon +1 )% tm.tm_mday % 1).str();
    uint32_t newser = atol(newserdate.c_str());
    if (newser <= soa2Update.serial)
      soa2Update.serial++;
    else
      soa2Update.serial = newser;
  }
  

  newRec.content = serializeSOAData(soa2Update);
  vector<DNSResourceRecord> rrset;
  rrset.push_back(newRec);
  di->backend->replaceRRSet(di->id, newRec.qname, newRec.qtype, rrset);

  //Correct ordername + auth flag
  if(haveNSEC3) {
    string hashed;
    if(!narrow) 
      hashed=toLower(toBase32Hex(hashQNameWithSalt(ns3pr->d_iterations, ns3pr->d_salt, newRec.qname)));
        
    di->backend->updateDNSSECOrderAndAuthAbsolute(di->id, newRec.qname, hashed, true);
  }
  else // NSEC
    di->backend->updateDNSSECOrderAndAuth(di->id, di->zone, newRec.qname, true);

  // purge the cache for the SOA record.
  PC.purge(newRec.qname); 
}
