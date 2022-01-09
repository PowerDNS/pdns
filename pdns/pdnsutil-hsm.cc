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
#include <boost/program_options.hpp>
#include <boost/assign/std/vector.hpp>
#include <boost/assign/list_of.hpp>
#include "dnsseckeeper.hh"
#include "dnssecinfra.hh"
#include "dnsbackend.hh"
#include "ueberbackend.hh"
#include "arguments.hh"
#include "pkcs11infra.hh"
#include "pkcs11signers.hh"
#include "pdnsutil.hh"

using namespace std;

int pdnsutil_cmd_hsm(const vector<string>& cmds, DNSSECKeeper& dk) {
#ifdef HAVE_P11KIT1
  UeberBackend B("default");
  if (cmds.size() < 2) {
    cerr << "Missing sub-command for pdnsutil hsm"<< std::endl;
    cerr << "Usage: pdnsutil hsm assign|create-key" << std::endl;
    return 0;
  }
  else if (cmds.at(1) == "assign") {
    DNSCryptoKeyEngine::storvector_t storvect;
    DomainInfo di;
    std::vector<DNSBackend::KeyData> keys;

    if (cmds.size() < 9) {
      std::cout << "Usage: pdnsutil hsm assign ZONE ALGORITHM {ksk|zsk} engine MODULE-NAME label LABEL publiclabel PUBLIC-LABEL id ID publicid ID tokenserial SERIAL tokenlabel TOKEN-LABEL slot SLOT-ID pin PIN" << std::endl;
      return 1;
    }

    DNSName zone(cmds.at(2));

    // verify zone
    if (!B.getDomainInfo(zone, di)) {
      cerr << "Unable to assign token to unknown zone '" << zone << "'" << std::endl;
      return 1;
    }

    int algorithm = DNSSECKeeper::shorthand2algorithm(cmds.at(3));
    if (algorithm<0) {
      cerr << "Cannot use unknown algorithm '" << cmds.at(3) << "'" << std::endl;
      return 1;
    }

    int64_t id;
    bool keyOrZone = (cmds.at(4) == "ksk" ? true : false);

    DNSKEYRecordContent drc;
    DNSSECPrivateKey dpk;
    dpk.d_flags = (keyOrZone ? 257 : 256);

    if ((cmds.size() - 5) % 2 != 0) {
      cerr << "Missing parameter after " << cmds.back() << endl;
      return 1;
    }

    const vector<std::string> knownKeys = {
      "engine", "label", "publiclabel", "id", "publicid", "tokenserial", "tokenlabel", "slot", "pin",
    };
    DNSCryptoKeyEngine::stormap_t stormap;
    stormap.emplace("algorithm", boost::lexical_cast<std::string>(algorithm));

    for(size_t i = 5; i < cmds.size(); i+=2) {
      string label = boost::to_lower_copy(cmds.at(i));
      if (find(knownKeys.begin(), knownKeys.end(), cmds.at(i)) == cmds.end()) {
        cerr << "Unsupported keyword '" << cmds.at(i) << "' given" << endl;
        return 1;
      }
      stormap.emplace(label, cmds.at(i+1));
    }

    if (stormap.count("engine") == 0) {
      cerr << "engine parameter is mandatory" << endl;
      return 1;
    }

    if (stormap.count("slot") == 0 &&
        stormap.count("tokenserial") == 0 &&
        stormap.count("tokenlabel") == 0) {
      cerr << "slot, tokenserial or tokenlabel must be provided" << endl;
      return 1;
    }

    shared_ptr<DNSCryptoKeyEngine> dke = make_shared<PKCS11DNSCryptoKeyEngine>(algorithm);
    dke->fromISCMap(drc, stormap);

    cout << dke->convertToISC() << endl;

    if(!dke->checkKey()) {
      cerr << "Invalid DNS Private Key in engine " << stormap.find("engine")->second << std::endl;
      return 1;
    }
    dpk.setKey(dke);

    // make sure this key isn't being reused.
    B.getDomainKeys(zone, keys);
    id = -1;

    for(DNSBackend::KeyData& kd :  keys) {
      if (kd.content == dke->convertToISC()) {
        // it's this one, I guess...
        id = kd.id;
        break;
      }
    }

    if (id > -1) {
      cerr << "You have already assigned this key with ID=" << id << std::endl;
      return 1;
    }

    if (!dk.addKey(zone, dpk, id)) {
      cerr << "Unable to assign token to zone" << std::endl;
      return 1;
    }

    cerr << "Assigned token to " << zone << " with key id " << id << endl;

    return 0;
  }
  else if (cmds.at(1) == "list") {
    if (cmds.size() < 3) {
      std::cout << "Usage: pdnsutil hsm list MODULE [PIN]" << std::endl;
      return 1;
    }
    auto module = std::make_shared<pdns::Pkcs11Module>(cmds.at(2));
    module->Initialize();
    auto& slots = module->GetSlots();
    for(auto& slot : slots) {
      if (!slot.second.HasToken() ||
          !slot.second.HasInitializedToken())
        continue;

      std::cout << "Slot ID: " << slot.first << std::endl;
      std::cout << "Serial : " << slot.second.GetSerialNumber() << std::endl;
      std::cout << "Label  : " << slot.second.GetLabel() << std::endl;

      auto session = slot.second.GetSession();
      if (cmds.size() > 3 && !session->Login(cmds.at(3))) {
        cerr << "Cannot login to slot" << endl;
        continue;
      }
      std::vector<CK_OBJECT_HANDLE> objects;
      std::vector<pdns::P11KitAttribute> attributes;
      attributes.push_back(pdns::P11KitAttribute(CKA_CLASS, (unsigned long)CKO_PUBLIC_KEY));
      if (session->FindObjects(attributes, objects) != CKR_OK) {
        cerr << "Cannot list objects from slot" << endl;
        continue;
      }
      attributes.clear();
      attributes.push_back(pdns::P11KitAttribute(CKA_CLASS, (unsigned long)CKO_PRIVATE_KEY));
      if (session->FindObjects(attributes, objects) != CKR_OK) {
        cerr << "Cannot list objects from slot" << endl;
        continue;
      }
      for (auto& object : objects) {
        attributes.clear();
        attributes.push_back(pdns::P11KitAttribute(CKA_ID, ""));
        attributes.push_back(pdns::P11KitAttribute(CKA_LABEL, ""));
        attributes.push_back(pdns::P11KitAttribute(CKA_KEY_TYPE, 0UL));
        attributes.push_back(pdns::P11KitAttribute(CKA_CLASS, 0UL));
        if (session->GetAttributeValue(object, attributes) != CKR_OK)
          continue;
        if (attributes[3].ulong() == CKO_PUBLIC_KEY)
          cout << "Public key object; ";
        else if (attributes[3].ulong() == CKO_PRIVATE_KEY)
          cout << "Private key object; ";
        else
          cout << "Unknown object; ";
        switch (attributes[2].ulong()) {
        case CKK_RSA:
          std::cout << "RSA";
          break;
        case CKK_EC:
          std::cout << "ECC";
          break;
        default:
          std::cout << "(" << attributes[2].ulong() << ")";
        }
        std::cout << std::endl;
        std::cout << " ID    : " << makeHexDump(attributes[0].str()) <<  std::endl;
        std::cout << " Label : " << attributes[1].str() << std::endl;
      }
    }
    return 0;
  }
  else if (cmds.at(1) == "create-key") {

    if (cmds.size() < 4) {
      cerr << "Usage: pdnsutil hsm create-key ZONE KEY-ID [BITS]" << endl;
      return 1;
    }
    DomainInfo di;
    DNSName zone(cmds.at(2));
    unsigned int id;
    int bits = 2048;
    // verify zone
    if (!B.getDomainInfo(zone, di)) {
      cerr << "Unable to create key for unknown zone '" << zone << "'" << std::endl;
      return 1;
    }

    id = pdns_stou(cmds.at(3));
    std::vector<DNSBackend::KeyData> keys;
    if (!B.getDomainKeys(zone, keys)) {
      cerr << "No keys found for zone " << zone << std::endl;
      return 1;
    }

    std::unique_ptr<DNSCryptoKeyEngine> dke = nullptr;
    // lookup correct key
    for(DNSBackend::KeyData &kd :  keys) {
      if (kd.id == id) {
        // found our key.
        DNSKEYRecordContent dkrc;
        dke = DNSCryptoKeyEngine::makeFromISCString(dkrc, kd.content);
      }
    }

    if (!dke) {
      cerr << "Could not find key with ID " << id << endl;
      return 1;
    }
    if (cmds.size() > 4) {
      bits = pdns_stou(cmds.at(4));
    }
    if (bits < 1) {
      cerr << "Invalid bit size " << bits << "given, must be positive integer";
      return 1;
    }
    try {
      dke->create(bits);
    } catch (PDNSException& e) {
       cerr << e.reason << endl;
       return 1;
    }

    cerr << "Key of size " << dke->getBits() << " created" << std::endl;
    return 0;
  } else {
    cerr << "Usage: pdnsutil hsm assign|create-key" << std::endl;
    return 1;
  }
#else
  cerr<<"PKCS#11 support not enabled"<<endl;
  return 1;
#endif
}
