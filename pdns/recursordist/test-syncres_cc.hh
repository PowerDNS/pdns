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
#pragma once

#include "arguments.hh"
#include "dnssecinfra.hh"
#include "dnsseckeeper.hh"
#include "rec-lua-conf.hh"
#include "syncres.hh"
#include "test-common.hh"
#include "validate-recursor.hh"

extern GlobalStateHolder<LuaConfigItems> g_luaconfs;

ArgvMap &arg();
int getMTaskerTID();

void primeHints(void);

void initSR(bool debug=false);
void initSR(std::unique_ptr<SyncRes>& sr, bool dnssec=false, bool debug=false, time_t fakeNow=0);

void setDNSSECValidation(std::unique_ptr<SyncRes>& sr, const DNSSECMode& mode);

void setLWResult(LWResult* res, int rcode, bool aa=false, bool tc=false, bool edns=false, bool validpacket=true);

void addRecordToLW(LWResult* res, const DNSName& name, uint16_t type, const std::string& content, DNSResourceRecord::Place place=DNSResourceRecord::ANSWER, uint32_t ttl=60);

void addRecordToLW(LWResult* res, const std::string& name, uint16_t type, const std::string& content, DNSResourceRecord::Place place=DNSResourceRecord::ANSWER, uint32_t ttl=60);

bool isRootServer(const ComboAddress& ip);


void computeRRSIG(const DNSSECPrivateKey& dpk, const DNSName& signer, const DNSName& signQName, uint16_t signQType, uint32_t signTTL, uint32_t sigValidity, RRSIGRecordContent& rrc, vector<shared_ptr<DNSRecordContent> >& toSign, boost::optional<uint8_t> algo=boost::none, boost::optional<uint32_t> inception=boost::none, boost::optional<time_t> now=boost::none);

typedef std::unordered_map<DNSName, std::pair<DNSSECPrivateKey, DSRecordContent> > testkeysset_t;

bool addRRSIG(const testkeysset_t& keys, std::vector<DNSRecord>& records, const DNSName& signer, uint32_t sigValidity, bool broken=false, boost::optional<uint8_t> algo=boost::none, boost::optional<DNSName> wildcard=boost::none, boost::optional<time_t> now=boost::none);


void addDNSKEY(const testkeysset_t& keys, const DNSName& signer, uint32_t ttl, std::vector<DNSRecord>& records);

bool addDS(const DNSName& domain, uint32_t ttl, std::vector<DNSRecord>& records, const testkeysset_t& keys, DNSResourceRecord::Place place=DNSResourceRecord::AUTHORITY);

void addNSECRecordToLW(const DNSName& domain, const DNSName& next, const std::set<uint16_t>& types,  uint32_t ttl, std::vector<DNSRecord>& records);

void addNSEC3RecordToLW(const DNSName& hashedName, const std::string& hashedNext, const std::string& salt, unsigned int iterations, const std::set<uint16_t>& types,  uint32_t ttl, std::vector<DNSRecord>& records);

void addNSEC3UnhashedRecordToLW(const DNSName& domain, const DNSName& zone, const std::string& next, const std::set<uint16_t>& types,  uint32_t ttl, std::vector<DNSRecord>& records, unsigned int iterations=10);

void addNSEC3NarrowRecordToLW(const DNSName& domain, const DNSName& zone, const std::set<uint16_t>& types,  uint32_t ttl, std::vector<DNSRecord>& records, unsigned int iterations=10);

void generateKeyMaterial(const DNSName& name, unsigned int algo, uint8_t digest, testkeysset_t& keys);

void generateKeyMaterial(const DNSName& name, unsigned int algo, uint8_t digest, testkeysset_t& keys, map<DNSName,dsmap_t>& dsAnchors);

int genericDSAndDNSKEYHandler(LWResult* res, const DNSName& domain, DNSName auth, int type, const testkeysset_t& keys, bool proveCut=true, boost::optional<time_t> now=boost::none);

int basicRecordsForQnameMinimization(LWResult* res, const DNSName& domain, int type);

