#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "packethandler.hh"
#include "qtype.hh"
#include "dnspacket.hh"
#include "auth-caches.hh"
#include "statbag.hh"
#include "dnsseckeeper.hh"
#include "base64.hh"
#include "base32.hh"

#include "misc.hh"
#include "arguments.hh"
#include "resolver.hh"
#include "dns_random.hh"
#include "backends/gsql/ssql.hh"
#include "communicator.hh"

extern StatBag S;
extern CommunicatorClass Communicator;

pthread_mutex_t PacketHandler::s_rfc2136lock=PTHREAD_MUTEX_INITIALIZER;

// Implement section 3.2.1 and 3.2.2 of RFC2136
int PacketHandler::checkUpdatePrerequisites(const DNSRecord *rr, DomainInfo *di) {
  if (rr->d_ttl != 0)
    return RCode::FormErr;

  // 3.2.1 and 3.2.2 check content length.
  if ( (rr->d_class == QClass::NONE || rr->d_class == QClass::ANY) && rr->d_clen != 0)
    return RCode::FormErr;

  bool foundRecord=false;
  DNSResourceRecord rec;
  di->backend->lookup(QType(QType::ANY), rr->d_name);
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
uint PacketHandler::performUpdate(const string &msgPrefix, const DNSRecord *rr, DomainInfo *di, bool isPresigned, bool* narrow, bool* haveNSEC3, NSEC3PARAMRecordContent *ns3pr, bool *updatedSerial) {

  QType rrType = QType(rr->d_type);

  if (rrType == QType::NSEC || rrType == QType::NSEC3) {
    L<<Logger::Warning<<msgPrefix<<"Trying to add/update/delete "<<rr->d_name<<"|"<<rrType.getName()<<". These are generated records, ignoring!"<<endl;
    return 0;
  }

  if (!isPresigned && ((!::arg().mustDo("direct-dnskey") && rrType == QType::DNSKEY) || rrType == QType::RRSIG)) {
    L<<Logger::Warning<<msgPrefix<<"Trying to add/update/delete "<<rr->d_name<<"|"<<rrType.getName()<<" in non-presigned zone, ignoring!"<<endl;
    return 0;
  }

  if ((rrType == QType::NSEC3PARAM || rrType == QType::DNSKEY) && rr->d_name != di->zone) {
    L<<Logger::Warning<<msgPrefix<<"Trying to add/update/delete "<<rr->d_name<<"|"<<rrType.getName()<<", "<<rrType.getName()<<" must be at zone apex, ignoring!"<<endl;
    return 0;
  }


  uint changedRecords = 0;
  DNSResourceRecord rec;
  vector<DNSResourceRecord> rrset, recordsToDelete;
  set<DNSName> delnonterm, insnonterm; // used to (at the end) fix ENT records.


  if (rr->d_class == QClass::IN) { // 3.4.2.2 QClass::IN means insert or update
    DLOG(L<<msgPrefix<<"Add/Update record (QClass == IN) "<<rr->d_name<<"|"<<rrType.getName()<<endl);

    if (rrType == QType::NSEC3PARAM) {
      L<<Logger::Notice<<msgPrefix<<"Adding/updating NSEC3PARAM for zone, resetting ordernames."<<endl;

      NSEC3PARAMRecordContent nsec3param(rr->d_content->getZoneRepresentation(), di->zone.toString() /* FIXME400 huh */);
      *narrow = false; // adding a NSEC3 will cause narrow mode to be dropped, as you cannot specify that in a NSEC3PARAM record
      d_dk.setNSEC3PARAM(di->zone, nsec3param, (*narrow));

      *haveNSEC3 = d_dk.getNSEC3PARAM(di->zone, ns3pr, narrow);

      vector<DNSResourceRecord> rrs;
      set<DNSName> qnames, nssets, dssets;
      di->backend->list(di->zone, di->id);
      while (di->backend->get(rec)) {
        qnames.insert(rec.qname);
        if(rec.qtype.getCode() == QType::NS && rec.qname != di->zone)
          nssets.insert(rec.qname);
        if(rec.qtype.getCode() == QType::DS)
          dssets.insert(rec.qname);
      }

      DNSName shorter;
      for(const auto& qname: qnames) {
        shorter = qname;
        int ddepth = 0;
        do {
          if(qname == di->zone)
            break;
          if(nssets.count(shorter))
            ++ddepth;
        } while(shorter.chopOff());

        DNSName ordername = DNSName(toBase32Hex(hashQNameWithSalt(*ns3pr, qname)));
        if (! *narrow && (ddepth == 0 || (ddepth == 1 && nssets.count(qname)))) {
          di->backend->updateDNSSECOrderNameAndAuth(di->id, qname, ordername, (ddepth == 0 ));

          if (nssets.count(qname)) {
            if (ns3pr->d_flags)
              di->backend->updateDNSSECOrderNameAndAuth(di->id, qname, DNSName(), false, QType::NS );
            di->backend->updateDNSSECOrderNameAndAuth(di->id, qname, DNSName(), false, QType::A);
            di->backend->updateDNSSECOrderNameAndAuth(di->id, qname, DNSName(), false, QType::AAAA);
          }
        } else {
          di->backend->updateDNSSECOrderNameAndAuth(di->id, qname, DNSName(), (ddepth == 0));
        }
        if (ddepth == 1 || dssets.count(qname)) // FIXME400 && ?
          di->backend->updateDNSSECOrderNameAndAuth(di->id, qname, ordername, false, QType::DS);
      }
      return 1;
    }



    bool foundRecord = false;
    di->backend->lookup(rrType, rr->d_name);
    while (di->backend->get(rec)) {
      rrset.push_back(rec);
      foundRecord = true;
    }

    if (foundRecord) {

      if (rrType == QType::SOA) { // SOA updates require the serial to be higher than the current
        SOAData sdOld, sdUpdate;
        DNSResourceRecord *oldRec = &rrset.front();
        fillSOAData(oldRec->content, sdOld);
        oldRec->setContent(rr->d_content->getZoneRepresentation());
        fillSOAData(oldRec->content, sdUpdate);
        if (rfc1982LessThan(sdOld.serial, sdUpdate.serial)) {
          di->backend->replaceRRSet(di->id, oldRec->qname, oldRec->qtype, rrset);
          *updatedSerial = true;
          changedRecords++;
          L<<Logger::Notice<<msgPrefix<<"Replacing record "<<rr->d_name<<"|"<<rrType.getName()<<endl;
        } else {
          L<<Logger::Notice<<msgPrefix<<"Provided serial ("<<sdUpdate.serial<<") is older than the current serial ("<<sdOld.serial<<"), ignoring SOA update."<<endl;
        }

      // It's not possible to have multiple CNAME's with the same NAME. So we always update.
      } else if (rrType == QType::CNAME) {
        int changedCNames = 0;
        for (vector<DNSResourceRecord>::iterator i = rrset.begin(); i != rrset.end(); i++) {
          if (i->ttl != rr->d_ttl || i->content != rr->d_content->getZoneRepresentation()) {
            i->ttl = rr->d_ttl;
            i->setContent(rr->d_content->getZoneRepresentation());
            changedCNames++;
          }
        }
        if (changedCNames > 0) {
          di->backend->replaceRRSet(di->id, rr->d_name, rrType, rrset);
          L<<Logger::Notice<<msgPrefix<<"Replacing record "<<rr->d_name<<"|"<<rrType.getName()<<endl;
          changedRecords += changedCNames;
        } else {
          L<<Logger::Notice<<msgPrefix<<"Replace for record "<<rr->d_name<<"|"<<rrType.getName()<<" requested, but no changes made."<<endl;
        }

      // In any other case, we must check if the TYPE and RDATA match to provide an update (which effectively means a update of TTL)
      } else {
        int updateTTL=0;
        foundRecord = false;
        for (vector<DNSResourceRecord>::iterator i = rrset.begin(); i != rrset.end(); i++) {
          string content = rr->d_content->getZoneRepresentation();
          if (rrType == i->qtype.getCode() && i->getZoneRepresentation() == content) {
            foundRecord=true;
            if (i->ttl != rr->d_ttl)  {
              i->ttl = rr->d_ttl;
              updateTTL++;
            }
          }
        }
        if (updateTTL > 0) {
          di->backend->replaceRRSet(di->id, rr->d_name, rrType, rrset);
          L<<Logger::Notice<<msgPrefix<<"Replacing record "<<rr->d_name<<"|"<<rrType.getName()<<endl;
          changedRecords += updateTTL;
        } else {
          L<<Logger::Notice<<msgPrefix<<"Replace for record "<<rr->d_name<<"|"<<rrType.getName()<<" requested, but no changes made."<<endl;
        }
      }

      // ReplaceRRSet dumps our ordername and auth flag, so we need to correct it if we have changed records.
      // We can take the auth flag from the first RR in the set, as the name is different, so should the auth be.
      if (changedRecords > 0) {
        bool auth = rrset.front().auth;

        if(*haveNSEC3) {
          DNSName ordername;
          if(! *narrow)
            ordername=DNSName(toBase32Hex(hashQNameWithSalt(*ns3pr, rr->d_name)));

          if (*narrow)
            di->backend->updateDNSSECOrderNameAndAuth(di->id, rr->d_name, DNSName(), auth);
          else
            di->backend->updateDNSSECOrderNameAndAuth(di->id, rr->d_name, ordername, auth);
          if(!auth || rrType == QType::DS) {
            di->backend->updateDNSSECOrderNameAndAuth(di->id, rr->d_name, DNSName(), false, QType::NS);
            di->backend->updateDNSSECOrderNameAndAuth(di->id, rr->d_name, DNSName(), false, QType::A);
            di->backend->updateDNSSECOrderNameAndAuth(di->id, rr->d_name, DNSName(), false, QType::AAAA);
          }

        } else { // NSEC
          di->backend->updateDNSSECOrderNameAndAuth(di->id, rr->d_name, rr->d_name.makeRelative(di->zone), auth);
          if(!auth || rrType == QType::DS) {
            di->backend->updateDNSSECOrderNameAndAuth(di->id, rr->d_name, DNSName(), false, QType::A);
            di->backend->updateDNSSECOrderNameAndAuth(di->id, rr->d_name, DNSName(), false, QType::AAAA);
          }
        }
      }

    } // if (foundRecord)

    // If we haven't found a record that matches, we must add it.
    if (! foundRecord) {
      L<<Logger::Notice<<msgPrefix<<"Adding record "<<rr->d_name<<"|"<<rrType.getName()<<endl;
      delnonterm.insert(rr->d_name); // always remove any ENT's in the place where we're going to add a record.
      auto newRec = DNSResourceRecord::fromWire(*rr);
      newRec.domain_id = di->id;
      newRec.auth = (rr->d_name == di->zone || rrType.getCode() != QType::NS);
      di->backend->feedRecord(newRec, DNSName());
      changedRecords++;


      // because we added a record, we need to fix DNSSEC data.
      DNSName shorter(rr->d_name);
      bool auth=newRec.auth;
      bool fixDS = (rrType == QType::DS);

      if (di->zone != shorter) { // Everything at APEX is auth=1 && no ENT's
        do {

          if (di->zone == shorter)
            break;

          bool foundShorter = false;
          di->backend->lookup(QType(QType::ANY), shorter);
          while (di->backend->get(rec)) {
            if (rec.qname == rr->d_name && rec.qtype == QType::DS)
              fixDS = true;
            if (shorter != rr->d_name)
              foundShorter = true;
            if (rec.qtype == QType::NS) // are we inserting below a delegate?
              auth=false;
          }

          if (!foundShorter && auth && shorter != rr->d_name) // haven't found any record at current level, insert ENT.
            insnonterm.insert(shorter);
          if (foundShorter)
            break; // if we find a shorter record, we can stop searching
        } while(shorter.chopOff());
      }

      if(*haveNSEC3)
      {
        DNSName ordername;
        if(! *narrow)
          ordername=DNSName(toBase32Hex(hashQNameWithSalt(*ns3pr, rr->d_name)));

        if (*narrow)
          di->backend->updateDNSSECOrderNameAndAuth(di->id, rr->d_name, DNSName(), auth);
        else
          di->backend->updateDNSSECOrderNameAndAuth(di->id, rr->d_name, ordername, auth);

        if (fixDS)
          di->backend->updateDNSSECOrderNameAndAuth(di->id, rr->d_name, ordername, true, QType::DS);

        if(!auth)
        {
          if (ns3pr->d_flags)
            di->backend->updateDNSSECOrderNameAndAuth(di->id, rr->d_name, DNSName(), false, QType::NS);
          di->backend->updateDNSSECOrderNameAndAuth(di->id, rr->d_name, DNSName(), false, QType::A);
          di->backend->updateDNSSECOrderNameAndAuth(di->id, rr->d_name, DNSName(), false, QType::AAAA);
        }
      }
      else // NSEC
      {
        DNSName ordername=rr->d_name.makeRelative(di->zone);
        di->backend->updateDNSSECOrderNameAndAuth(di->id, rr->d_name, ordername, auth);
        if (fixDS) {
          di->backend->updateDNSSECOrderNameAndAuth(di->id, rr->d_name, ordername, true, QType::DS);
        }
        if(!auth) {
          di->backend->updateDNSSECOrderNameAndAuth(di->id, rr->d_name, DNSName(), false, QType::A);
          di->backend->updateDNSSECOrderNameAndAuth(di->id, rr->d_name, DNSName(), false, QType::AAAA);
        }
      }


      // If we insert an NS, all the records below it become non auth - so, we're inserting a delegate.
      // Auth can only be false when the rr->d_name is not the zone
      if (auth == false && rrType == QType::NS) {
        DLOG(L<<msgPrefix<<"Going to fix auth flags below "<<rr->d_name<<endl);
        insnonterm.clear(); // No ENT's are needed below delegates (auth=0)
        vector<DNSName> qnames;
        di->backend->listSubZone(rr->d_name, di->id);
        while(di->backend->get(rec)) {
          if (rec.qtype.getCode() && rec.qtype.getCode() != QType::DS && rr->d_name != rec.qname) // Skip ENT, DS and our already corrected record.
            qnames.push_back(rec.qname);
        }
        for(vector<DNSName>::const_iterator qname=qnames.begin(); qname != qnames.end(); ++qname) {
          if(*haveNSEC3)  {
            DNSName ordername;
            if(! *narrow)
              ordername=DNSName(toBase32Hex(hashQNameWithSalt(*ns3pr, *qname)));

            if (*narrow)
              di->backend->updateDNSSECOrderNameAndAuth(di->id, rr->d_name, DNSName(), auth); // FIXME400 no *qname here?
            else
              di->backend->updateDNSSECOrderNameAndAuth(di->id, *qname, ordername, auth);

            if (ns3pr->d_flags)
              di->backend->updateDNSSECOrderNameAndAuth(di->id, *qname, DNSName(), false, QType::NS);
          }
          else { // NSEC
            DNSName ordername=DNSName(*qname).makeRelative(di->zone);
            di->backend->updateDNSSECOrderNameAndAuth(di->id, *qname, ordername, false, QType::NS);
          }

          di->backend->updateDNSSECOrderNameAndAuth(di->id, *qname, DNSName(), false, QType::A);
          di->backend->updateDNSSECOrderNameAndAuth(di->id, *qname, DNSName(), false, QType::AAAA);
        }
      }
    }
  } // rr->d_class == QClass::IN


  // Delete records - section 3.4.2.3 and 3.4.2.4 with the exception of the 'always leave 1 NS rule' as that's handled by
  // the code that calls this performUpdate().
  if ((rr->d_class == QClass::ANY || rr->d_class == QClass::NONE) && rrType != QType::SOA) { // never delete a SOA.
    DLOG(L<<msgPrefix<<"Deleting records: "<<rr->d_name<<"; QClass:"<<rr->d_class<<"; rrType: "<<rrType.getName()<<endl);

    if (rrType == QType::NSEC3PARAM) {
      L<<Logger::Notice<<msgPrefix<<"Deleting NSEC3PARAM from zone, resetting ordernames."<<endl;
      if (rr->d_class == QClass::ANY)
        d_dk.unsetNSEC3PARAM(rr->d_name);
      else if (rr->d_class == QClass::NONE) {
        NSEC3PARAMRecordContent nsec3rr(rr->d_content->getZoneRepresentation(), di->zone.toString() /* FIXME400 huh */);
        if (ns3pr->getZoneRepresentation() == nsec3rr.getZoneRepresentation())
          d_dk.unsetNSEC3PARAM(rr->d_name);
        else
          return 0;
      } else
        return 0;

      // We retrieve new values, other RR's in this update package might need it as well.
      *haveNSEC3 = d_dk.getNSEC3PARAM(di->zone, ns3pr, narrow);

      vector<DNSResourceRecord> rrs;
      set<DNSName> qnames, nssets, dssets, ents;
      di->backend->list(di->zone, di->id);
      while (di->backend->get(rec)) {
        qnames.insert(rec.qname);
        if(rec.qtype.getCode() == QType::NS && rec.qname != di->zone)
          nssets.insert(rec.qname);
        if(rec.qtype.getCode() == QType::DS)
          dssets.insert(rec.qname);
        if(!rec.qtype.getCode())
          ents.insert(rec.qname);
      }

      DNSName shorter;
      string hashed;
      for(const DNSName& qname :  qnames) {
        shorter = qname;
        int ddepth = 0;
        do {
          if(qname == di->zone)
            break;
          if(nssets.count(shorter))
            ++ddepth;
        } while(shorter.chopOff());

        DNSName ordername=qname.makeRelative(di->zone);
        if (!ents.count(qname) && (ddepth == 0 || (ddepth == 1 && nssets.count(qname)))) {
          di->backend->updateDNSSECOrderNameAndAuth(di->id, qname, ordername, (ddepth == 0));

          if (nssets.count(qname)) {
            di->backend->updateDNSSECOrderNameAndAuth(di->id, qname, DNSName(), false, QType::A);
            di->backend->updateDNSSECOrderNameAndAuth(di->id, qname, DNSName(), false, QType::AAAA);
          }
        } else {
          di->backend->updateDNSSECOrderNameAndAuth(di->id, qname, DNSName(), (ddepth == 0));
        }
        if (ddepth == 1 || dssets.count(qname))
          di->backend->updateDNSSECOrderNameAndAuth(di->id, qname, ordername, true, QType::DS);
      }
      return 1;
    } // end of NSEC3PARAM delete block


    di->backend->lookup(rrType, rr->d_name);
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
  
    if (recordsToDelete.size()) {
      di->backend->replaceRRSet(di->id, rr->d_name, rrType, rrset);
      L<<Logger::Notice<<msgPrefix<<"Deleting record "<<rr->d_name<<"|"<<rrType.getName()<<endl;
      changedRecords += recordsToDelete.size();


      // If we've removed a delegate, we need to reset ordername/auth for some records.
      if (rrType == QType::NS && rr->d_name != di->zone) { 
        vector<DNSName> belowOldDelegate, nsRecs, updateAuthFlag;
        di->backend->listSubZone(rr->d_name, di->id);
        while (di->backend->get(rec)) {
          if (rec.qtype.getCode()) // skip ENT records, they are always auth=false
            belowOldDelegate.push_back(rec.qname);
          if (rec.qtype.getCode() == QType::NS && rec.qname != rr->d_name)
            nsRecs.push_back(rec.qname);
        }

        for(auto &belowOldDel: belowOldDelegate)
        {
          bool isBelowDelegate = false;
          for(const auto & ns: nsRecs) {
            if (ns.isPartOf(belowOldDel)) {
              isBelowDelegate=true;
              break;
            }
          }
          if (!isBelowDelegate)
            updateAuthFlag.push_back(belowOldDel);
        }

        for (const auto &changeRec:updateAuthFlag) {
          if(*haveNSEC3)  {
            DNSName ordername;
            if(! *narrow)
              ordername=DNSName(toBase32Hex(hashQNameWithSalt(*ns3pr, changeRec)));

            di->backend->updateDNSSECOrderNameAndAuth(di->id, changeRec, ordername, true);
          }
          else { // NSEC
            DNSName ordername=changeRec.makeRelative(di->zone);
            di->backend->updateDNSSECOrderNameAndAuth(di->id, changeRec, ordername, true);
          }
        }
      }

      // Fix ENT records.
      // We must check if we have a record below the current level and if we removed the 'last' record
      // on that level. If so, we must insert an ENT record.
      // We take extra care here to not 'include' the record that we just deleted. Some backends will still return it as they only reload on a commit.
      bool foundDeeper = false, foundOtherWithSameName = false;
      di->backend->listSubZone(rr->d_name, di->id);
      while (di->backend->get(rec)) {
        if (rec.qname == rr->d_name && !count(recordsToDelete.begin(), recordsToDelete.end(), rec))
          foundOtherWithSameName = true;
        if (rec.qname != rr->d_name && rec.qtype.getCode() != QType::NS) //Skip NS records, as this would be a delegate that we can ignore as this does not require us to create a ENT
          foundDeeper = true;
      }

      if (foundDeeper && !foundOtherWithSameName) {
        insnonterm.insert(rr->d_name);
      } else if (!foundOtherWithSameName) {
        // If we didn't have to insert an ENT, we might have deleted a record at very deep level
        // and we must then clean up the ENT's above the deleted record.
        DNSName shorter(rr->d_name);
        while (shorter != di->zone) {
          shorter.chopOff();
          bool foundRealRR = false;
          bool foundEnt = false;

          // The reason for a listSubZone here is because might go up the tree and find the ENT of another branch
          // consider these non ENT-records:
          // b.c.d.e.test.com
          // b.d.e.test.com
          // if we delete b.c.d.e.test.com, we go up to d.e.test.com and then find b.d.e.test.com because that's below d.e.test.com.
          // At that point we can stop deleting ENT's because the tree is in tact again.
          di->backend->listSubZone(shorter, di->id);

          while (di->backend->get(rec)) {
            if (rec.qtype.getCode())
              foundRealRR = true;
            else
              foundEnt = true;
          }
          if (!foundRealRR) {
            if (foundEnt) // only delete the ENT if we actually found one.
              delnonterm.insert(shorter);
          } else
            break;
        }
      }
    } else { // if (recordsToDelete.size())
      L<<Logger::Notice<<msgPrefix<<"Deletion for record "<<rr->d_name<<"|"<<rrType.getName()<<" requested, but not found."<<endl;
    }
  } // (End of delete block d_class == ANY || d_class == NONE
  


  //Insert and delete ENT's
  if (insnonterm.size() > 0 || delnonterm.size() > 0) {
    DLOG(L<<msgPrefix<<"Updating ENT records - "<<insnonterm.size()<<"|"<<delnonterm.size()<<endl);
    di->backend->updateEmptyNonTerminals(di->id, insnonterm, delnonterm, false);
    for (const auto &i: insnonterm) {
      string hashed;
      if(*haveNSEC3)
      {
        DNSName ordername;
        if(! *narrow)
          ordername=DNSName(toBase32Hex(hashQNameWithSalt(*ns3pr, i)));
        di->backend->updateDNSSECOrderNameAndAuth(di->id, i, ordername, true);
      }
    }
  }

  return changedRecords;
}

int PacketHandler::forwardPacket(const string &msgPrefix, DNSPacket *p, DomainInfo *di) {
  vector<string> forward;
  B.getDomainMetadata(p->qdomain, "FORWARD-DNSUPDATE", forward);

  if (forward.size() == 0 && ! ::arg().mustDo("forward-dnsupdate")) {
    L<<Logger::Notice<<msgPrefix<<"Not configured to forward to master, returning Refused."<<endl;
    return RCode::Refused;
  }

  for(vector<string>::const_iterator master=di->masters.begin(); master != di->masters.end(); master++) {
    L<<Logger::Notice<<msgPrefix<<"Forwarding packet to master "<<*master<<endl;
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
    if(sock < 0) {
      L<<Logger::Error<<msgPrefix<<"Error creating socket: "<<stringerror()<<endl;
      continue;
    }

    if( connect(sock, (struct sockaddr*)&remote, remote.getSocklen()) < 0 ) {
      L<<Logger::Error<<msgPrefix<<"Failed to connect to "<<remote.toStringWithPort()<<": "<<stringerror()<<endl;
      try {
        closesocket(sock);
      }
      catch(const PDNSException& e) {
        L<<Logger::Error<<"Error closing master forwarding socket after connect() failed: "<<e.reason<<endl;
      }
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
      try {
        closesocket(sock);
      }
      catch(const PDNSException& e) {
        L<<Logger::Error<<"Error closing master forwarding socket after write() failed: "<<e.reason<<endl;
      }
      continue;
    }

    int res = waitForData(sock, 10, 0);
    if (!res) {
      L<<Logger::Error<<msgPrefix<<"Timeout waiting for reply from master at "<<remote.toStringWithPort()<<endl;
      try {
        closesocket(sock);
      }
      catch(const PDNSException& e) {
        L<<Logger::Error<<"Error closing master forwarding socket after a timeout occured: "<<e.reason<<endl;
      }
      continue;
    }
    if (res < 0) {
      L<<Logger::Error<<msgPrefix<<"Error waiting for answer from master at "<<remote.toStringWithPort()<<", error:"<<stringerror()<<endl;
      try {
        closesocket(sock);
      }
      catch(const PDNSException& e) {
        L<<Logger::Error<<"Error closing master forwarding socket after an error occured: "<<e.reason<<endl;
      }
      continue;
    }

    unsigned char lenBuf[2];
    ssize_t recvRes;
    recvRes = recv(sock, &lenBuf, sizeof(lenBuf), 0);
    if (recvRes < 0 || static_cast<size_t>(recvRes) < sizeof(lenBuf)) {
      L<<Logger::Error<<msgPrefix<<"Could not receive data (length) from master at "<<remote.toStringWithPort()<<", error:"<<stringerror()<<endl;
      try {
        closesocket(sock);
      }
      catch(const PDNSException& e) {
        L<<Logger::Error<<"Error closing master forwarding socket after recv() failed: "<<e.reason<<endl;
      }
      continue;
    }
    size_t packetLen = lenBuf[0]*256+lenBuf[1];

    char buf[packetLen];
    recvRes = recv(sock, &buf, packetLen, 0);
    if (recvRes < 0) {
      L<<Logger::Error<<msgPrefix<<"Could not receive data (dnspacket) from master at "<<remote.toStringWithPort()<<", error:"<<stringerror()<<endl;
      try {
        closesocket(sock);
      }
      catch(const PDNSException& e) {
        L<<Logger::Error<<"Error closing master forwarding socket after recv() failed: "<<e.reason<<endl;
      }
      continue;
    }
    try {
      closesocket(sock);
    }
    catch(const PDNSException& e) {
      L<<Logger::Error<<"Error closing master forwarding socket: "<<e.reason<<endl;
    }

    try {
      MOADNSParser mdp(false, buf, static_cast<unsigned int>(recvRes));
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
  if (! ::arg().mustDo("dnsupdate"))
    return RCode::Refused;

  string msgPrefix="UPDATE (" + itoa(p->d.id) + ") from " + p->getRemote().toString() + " for " + p->qdomain.toLogString() + ": ";
  L<<Logger::Info<<msgPrefix<<"Processing started."<<endl;

  // if there is policy, we delegate all checks to it
  if (this->d_update_policy_lua == NULL) {

    // Check permissions - IP based
    vector<string> allowedRanges;
    B.getDomainMetadata(p->qdomain, "ALLOW-DNSUPDATE-FROM", allowedRanges);
    if (! ::arg()["allow-dnsupdate-from"].empty())
      stringtok(allowedRanges, ::arg()["allow-dnsupdate-from"], ", \t" );

    NetmaskGroup ng;
    for(vector<string>::const_iterator i=allowedRanges.begin(); i != allowedRanges.end(); i++)
      ng.addMask(*i);

    if ( ! ng.match(&p->d_remote)) {
      L<<Logger::Error<<msgPrefix<<"Remote not listed in allow-dnsupdate-from or domainmetadata. Sending REFUSED"<<endl;
      return RCode::Refused;
    }


    // Check permissions - TSIG based.
    vector<string> tsigKeys;
    B.getDomainMetadata(p->qdomain, "TSIG-ALLOW-DNSUPDATE", tsigKeys);
    if (tsigKeys.size() > 0) {
      bool validKey = false;

      TSIGRecordContent trc;
      DNSName inputkey;
      string message;
      if (! p->getTSIGDetails(&trc,  &inputkey)) {
        L<<Logger::Error<<msgPrefix<<"TSIG key required, but packet does not contain key. Sending REFUSED"<<endl;
        return RCode::Refused;
      }

      if (p->d_tsig_algo == TSIG_GSS) {
        GssName inputname(p->d_peer_principal); // match against principal since GSS
        for(vector<string>::const_iterator key=tsigKeys.begin(); key != tsigKeys.end(); key++) {
          if (inputname.match(*key)) {
            validKey = true;
            break;
          }
        }
      } else {
        for(vector<string>::const_iterator key=tsigKeys.begin(); key != tsigKeys.end(); key++) {
          if (inputkey == DNSName(*key)) { // because checkForCorrectTSIG has already been performed earlier on, if the names of the ky match with the domain given. THis is valid.
            validKey=true;
            break;
          }
        }
      }

      if (!validKey) {
        L<<Logger::Error<<msgPrefix<<"TSIG key ("<<inputkey<<") required, but no matching key found in domainmetadata, tried "<<tsigKeys.size()<<". Sending REFUSED"<<endl;
        return RCode::Refused;
      }
    }

    if (tsigKeys.size() == 0 && p->d_havetsig)
      L<<Logger::Warning<<msgPrefix<<"TSIG is provided, but domain is not secured with TSIG. Processing continues"<<endl;

  }

  // RFC2136 uses the same DNS Header and Message as defined in RFC1035.
  // This means we can use the MOADNSParser to parse the incoming packet. The result is that we have some different
  // variable names during the use of our MOADNSParser.
  MOADNSParser mdp(false, p->getString());
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
    L<<Logger::Error<<msgPrefix<<"Can't determine backend for domain '"<<p->qdomain<<"' (or backend does not support DNS update operation)"<<endl;
    return RCode::NotAuth;
  }

  if (di.kind == DomainInfo::Slave)
    return forwardPacket(msgPrefix, p, &di);

  // Check if all the records provided are within the zone
  for(MOADNSParser::answers_t::const_iterator i=mdp.d_answers.begin(); i != mdp.d_answers.end(); ++i) {
    const DNSRecord *rr = &i->first;
    // Skip this check for other field types (like the TSIG -  which is in the additional section)
    // For a TSIG, the label is the dnskey, so it does not pass the endOn validation.
    if (! (rr->d_place == DNSResourceRecord::ANSWER || rr->d_place == DNSResourceRecord::AUTHORITY))
      continue;

    if (!rr->d_name.isPartOf(di.zone)) {
      L<<Logger::Error<<msgPrefix<<"Received update/record out of zone, sending NotZone."<<endl;
      return RCode::NotZone;
    }
  }


  Lock l(&s_rfc2136lock); //TODO: i think this lock can be per zone, not for everything
  L<<Logger::Info<<msgPrefix<<"starting transaction."<<endl;
  if (!di.backend->startTransaction(p->qdomain, -1)) { // Not giving the domain_id means that we do not delete the existing records.
    L<<Logger::Error<<msgPrefix<<"Backend for domain "<<p->qdomain<<" does not support transaction. Can't do Update packet."<<endl;
    return RCode::NotImp;
  }

  // 3.2.1 and 3.2.2 - Prerequisite check
  for(MOADNSParser::answers_t::const_iterator i=mdp.d_answers.begin(); i != mdp.d_answers.end(); ++i) {
    const DNSRecord *rr = &i->first;
    if (rr->d_place == DNSResourceRecord::ANSWER) {
      int res = checkUpdatePrerequisites(rr, &di);
      if (res>0) {
        L<<Logger::Error<<msgPrefix<<"Failed PreRequisites check, returning "<<res<<endl;
        di.backend->abortTransaction();
        return res;
      }
    }
  }

  // 3.2.3 - Prerequisite check - this is outside of updatePrerequisitesCheck because we check an RRSet and not the RR.
  typedef pair<DNSName, QType> rrSetKey_t;
  typedef vector<DNSResourceRecord> rrVector_t;
  typedef std::map<rrSetKey_t, rrVector_t> RRsetMap_t;
  RRsetMap_t preReqRRsets;
  for(const auto& i : mdp.d_answers) {
    const DNSRecord* rr = &i.first;
    if (rr->d_place == DNSResourceRecord::ANSWER) {
      // Last line of 3.2.3
      if (rr->d_class != QClass::IN && rr->d_class != QClass::NONE && rr->d_class != QClass::ANY)
        return RCode::FormErr;

      if (rr->d_class == QClass::IN) {
        rrSetKey_t key = make_pair(rr->d_name, QType(rr->d_type));
        rrVector_t *vec = &preReqRRsets[key];
        vec->push_back(DNSResourceRecord::fromWire(*rr));
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



  // 3.4 - Prescan & Add/Update/Delete records - is all done within a try block.
  try {
    uint changedRecords = 0;
    // 3.4.1 - Prescan section
    for(MOADNSParser::answers_t::const_iterator i=mdp.d_answers.begin(); i != mdp.d_answers.end(); ++i) {
      const DNSRecord *rr = &i->first;
      if (rr->d_place == DNSResourceRecord::AUTHORITY) {
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
    bool narrow=false;
    bool haveNSEC3 = d_dk.getNSEC3PARAM(di.zone, &ns3pr, &narrow);
    bool isPresigned = d_dk.isPresigned(di.zone);

    // 3.4.2 - Perform the updates.
    // There's a special condition where deleting the last NS record at zone apex is never deleted (3.4.2.4)
    // This means we must do it outside the normal performUpdate() because that focusses only on a separate RR.
    vector<const DNSRecord *> nsRRtoDelete;
    for(MOADNSParser::answers_t::const_iterator i=mdp.d_answers.begin(); i != mdp.d_answers.end(); ++i) {
      const DNSRecord *rr = &i->first;
      if (rr->d_place == DNSResourceRecord::AUTHORITY) {
        /* see if it's permitted by policy */
        if (this->d_update_policy_lua != NULL) {
          if (this->d_update_policy_lua->updatePolicy(rr->d_name, QType(rr->d_type), di.zone, p) == false) {
            L<<Logger::Warning<<msgPrefix<<"Refusing update for " << rr->d_name << "/" << QType(rr->d_type).getName() << ": Not permitted by policy"<<endl;
            continue;
          } else {
            L<<Logger::Debug<<msgPrefix<<"Accepting update for " << rr->d_name << "/" << QType(rr->d_type).getName() << ": Permitted by policy"<<endl;
          }
        }

        if (rr->d_class == QClass::NONE  && rr->d_type == QType::NS && rr->d_name == di.zone)
          nsRRtoDelete.push_back(rr);
        else
          changedRecords += performUpdate(msgPrefix, rr, &di, isPresigned, &narrow, &haveNSEC3, &ns3pr, &updatedSerial);
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
              changedRecords += performUpdate(msgPrefix, *rr, &di, isPresigned, &narrow, &haveNSEC3, &ns3pr, &updatedSerial);
          }
        }
      }
    }

    // Section 3.6 - Update the SOA serial - outside of performUpdate because we do a SOA update for the complete update message
    if (changedRecords > 0 && !updatedSerial) {
      increaseSerial(msgPrefix, &di, haveNSEC3, narrow, &ns3pr);
      changedRecords++;
    }

    if (changedRecords > 0) {
      if (!di.backend->commitTransaction()) {
       L<<Logger::Error<<msgPrefix<<"Failed to commit updates!"<<endl;
        return RCode::ServFail;
      }

      S.deposit("dnsupdate-changes", changedRecords);

      // Purge the records!
      string zone(di.zone.toString());
      zone.append("$");
      purgeAuthCaches(zone);

      // Notify slaves
      if (di.kind == DomainInfo::Master) {
        vector<string> notify;
        B.getDomainMetadata(p->qdomain, "NOTIFY-DNSUPDATE", notify);
        if (!notify.empty() && notify.front() == "1") {
          Communicator.notifyDomain(di.zone);
        }
      }

      L<<Logger::Info<<msgPrefix<<"Update completed, "<<changedRecords<<" changed records committed."<<endl;
    } else {
      //No change, no commit, we perform abort() because some backends might like this more.
      L<<Logger::Info<<msgPrefix<<"Update completed, 0 changes, rolling back."<<endl;
      di.backend->abortTransaction();
    }
    return RCode::NoError; //rfc 2136 3.4.2.5
  }
  catch (SSqlException &e) {
    L<<Logger::Error<<msgPrefix<<"Caught SSqlException: "<<e.txtReason()<<"; Sending ServFail!"<<endl;
    di.backend->abortTransaction();
    return RCode::ServFail;
  }
  catch (DBException &e) {
    L<<Logger::Error<<msgPrefix<<"Caught DBException: "<<e.reason<<"; Sending ServFail!"<<endl;
    di.backend->abortTransaction();
    return RCode::ServFail;
  }
  catch (PDNSException &e) {
    L<<Logger::Error<<msgPrefix<<"Caught PDNSException: "<<e.reason<<"; Sending ServFail!"<<endl;
    di.backend->abortTransaction();
    return RCode::ServFail;
  }
  catch(std::exception &e) {
    L<<Logger::Error<<msgPrefix<<"Caught std:exception: "<<e.what()<<"; Sending ServFail!"<<endl;
    di.backend->abortTransaction();
    return RCode::ServFail;
  }
  catch (...) {
    L<<Logger::Error<<msgPrefix<<"Caught unknown exception when performing update. Sending ServFail!"<<endl;
    di.backend->abortTransaction();
    return RCode::ServFail;
  }
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
    throw PDNSException("SOA-Serial update failed because there was no SOA. Wowie.");
  }
  SOAData soa2Update;
  fillSOAData(rec.content, soa2Update);
  uint32_t oldSerial = soa2Update.serial;

  if (oldSerial == 0) { // using Autoserial, leave the serial alone.
    L<<Logger::Notice<<msgPrefix<<"AutoSerial being used, not updating SOA serial."<<endl;
    return;
  }

  vector<string> soaEdit2136Setting;
  B.getDomainMetadata(di->zone, "SOA-EDIT-DNSUPDATE", soaEdit2136Setting);
  string soaEdit2136 = "DEFAULT";
  string soaEdit;
  if (!soaEdit2136Setting.empty()) {
    soaEdit2136 = soaEdit2136Setting[0];
    if (pdns_iequals(soaEdit2136, "SOA-EDIT") || pdns_iequals(soaEdit2136,"SOA-EDIT-INCREASE") ){
      string soaEditSetting;
      d_dk.getSoaEdit(di->zone, soaEditSetting);
      if (soaEditSetting.empty()) {
        L<<Logger::Error<<msgPrefix<<"Using "<<soaEdit2136<<" for SOA-EDIT-DNSUPDATE increase on DNS update, but SOA-EDIT is not set for domain \""<< di->zone <<"\". Using DEFAULT for SOA-EDIT-DNSUPDATE"<<endl;
        soaEdit2136 = "DEFAULT";
      } else
        soaEdit = soaEditSetting;
    }
  }

  soa2Update.serial = calculateIncreaseSOA(soa2Update, soaEdit2136, soaEdit);

  newRec.content = serializeSOAData(soa2Update);
  vector<DNSResourceRecord> rrset;
  rrset.push_back(newRec);
  di->backend->replaceRRSet(di->id, newRec.qname, newRec.qtype, rrset);
  L<<Logger::Notice<<msgPrefix<<"Increasing SOA serial ("<<oldSerial<<" -> "<<soa2Update.serial<<")"<<endl;

  //Correct ordername + auth flag
  if (haveNSEC3 && narrow)
    di->backend->updateDNSSECOrderNameAndAuth(di->id, newRec.qname, DNSName(), true);
  else if (haveNSEC3) {
    DNSName ordername;
    if (!narrow)
      ordername = DNSName(toBase32Hex(hashQNameWithSalt(*ns3pr, newRec.qname)));

    di->backend->updateDNSSECOrderNameAndAuth(di->id, newRec.qname, ordername, true);
  }
  else { // NSEC
    DNSName ordername=newRec.qname.makeRelative(di->zone);
    di->backend->updateDNSSECOrderNameAndAuth(di->id, newRec.qname, ordername, true);
  }
}
