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
      std::cout << "Usage: pdnsutil hsm assign ZONE ALGORITHM {ksk|zsk} MODULE TOKEN PIN LABEL (PUBLABEL)" << std::endl;
      return 1;
    }

    DNSName zone(cmds.at(2));

    // verify zone
    if (!B.getDomainInfo(zone, di)) {
      cerr << "Unable to assign module to unknown zone '" << zone << "'" << std::endl;
      return 1;
    }

    int algorithm = DNSSECKeeper::shorthand2algorithm(cmds.at(3));
    if (algorithm<0) {
      cerr << "Unable to use unknown algorithm '" << cmds.at(3) << "'" << std::endl;
      return 1;
    }

    int64_t id;
    bool keyOrZone = (cmds.at(4) == "ksk" ? true : false);
    string module = cmds.at(5);
    string slot = cmds.at(6);
    string pin = cmds.at(7);
    string label = cmds.at(8);
    string pub_label;
    if (cmds.size() > 9)
      pub_label = cmds.at(9);
    else
       pub_label = label;

    std::ostringstream iscString;
    iscString << "Private-key-format: v1.2" << std::endl <<
      "Algorithm: " << algorithm << std::endl <<
      "Engine: " << module << std::endl <<
      "Slot: " << slot << std::endl <<
      "PIN: " << pin << std::endl <<
      "Label: " << label << std::endl <<
      "PubLabel: " << pub_label << std::endl;

    DNSKEYRecordContent drc;
    DNSSECPrivateKey dpk;
    dpk.d_flags = (keyOrZone ? 257 : 256);

    shared_ptr<DNSCryptoKeyEngine> dke(DNSCryptoKeyEngine::makeFromISCString(drc, iscString.str()));
    if(!dke->checkKey()) {
      cerr << "Invalid DNS Private Key in engine " << module << " slot " << slot << std::endl;
      return 1;
    }
    dpk.setKey(dke);

    // make sure this key isn't being reused.
    B.getDomainKeys(zone, keys);
    id = -1;

    for(DNSBackend::KeyData& kd :  keys) {
      if (kd.content == iscString.str()) {
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
      cerr << "Unable to assign module slot to zone" << std::endl;
      return 1;
    }

    cerr << "Module " << module << " slot " << slot << " assigned to " << zone << " with key id " << id << endl;

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
