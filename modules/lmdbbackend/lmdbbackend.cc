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

#include "ext/lmdb-safe/lmdb-safe.hh"
#include <lmdb.h>
#include <stdexcept>
#include <utility>
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "pdns/utility.hh"
#include "pdns/dnsbackend.hh"
#include "pdns/dns.hh"
#include "pdns/dnspacket.hh"
#include "pdns/base32.hh"
#include "pdns/dnssecinfra.hh"
#include "pdns/pdnsexception.hh"
#include "pdns/logger.hh"
#include "pdns/version.hh"
#include "pdns/arguments.hh"
#include "pdns/lock.hh"
#include "pdns/uuid-utils.hh"
#include <boost/archive/binary_oarchive.hpp>
#include <boost/archive/binary_iarchive.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/serialization/string.hpp>
#include <boost/serialization/utility.hpp>
#include <boost/uuid/uuid_serialize.hpp>

#include <boost/iostreams/device/back_inserter.hpp>

#ifdef HAVE_SYSTEMD
#include <systemd/sd-daemon.h>
#endif

#include <stdio.h>
#include <unistd.h>

#include "lmdbbackend.hh"

#define SCHEMAVERSION 5

// List the class version here. Default is 0
BOOST_CLASS_VERSION(LMDBBackend::KeyDataDB, 1)
BOOST_CLASS_VERSION(DomainInfo, 1)

static bool s_first = true;
static int s_shards = 0;
static std::mutex s_lmdbStartupLock;

std::pair<uint32_t, uint32_t> LMDBBackend::getSchemaVersionAndShards(std::string& filename)
{
  // cerr << "getting schema version for path " << filename << endl;

  uint32_t schemaversion;

  int rc;
  MDB_env* env = nullptr;

  if ((rc = mdb_env_create(&env)) != 0) {
    throw std::runtime_error("mdb_env_create failed");
  }

  if ((rc = mdb_env_set_mapsize(env, 0)) != 0) {
    throw std::runtime_error("mdb_env_set_mapsize failed");
  }

  if ((rc = mdb_env_set_maxdbs(env, 20)) != 0) { // we need 17: 1 {"pdns"} + 4 {"domains", "keydata", "tsig", "metadata"} * 2 {v4, v5} * 2 {main, index in _0}
    mdb_env_close(env);
    throw std::runtime_error("mdb_env_set_maxdbs failed");
  }

  if ((rc = mdb_env_open(env, filename.c_str(), MDB_NOSUBDIR | MDB_RDONLY, 0600)) != 0) {
    if (rc == ENOENT) {
      // we don't have a database yet! report schema 0, with 0 shards
      return {0u, 0u};
    }
    mdb_env_close(env);
    throw std::runtime_error("mdb_env_open failed");
  }

  MDB_txn* txn = nullptr;

  if ((rc = mdb_txn_begin(env, NULL, MDB_RDONLY, &txn)) != 0) {
    mdb_env_close(env);
    throw std::runtime_error("mdb_txn_begin failed");
  }

  MDB_dbi dbi;

  if ((rc = mdb_dbi_open(txn, "pdns", 0, &dbi)) != 0) {
    if (rc == MDB_NOTFOUND) {
      // this means nothing has been inited yet
      // we pretend this means 5
      mdb_txn_abort(txn);
      mdb_env_close(env);
      return {5u, 0u};
    }
    mdb_txn_abort(txn);
    mdb_env_close(env);
    throw std::runtime_error("mdb_dbi_open failed");
  }

  MDB_val key, data;

  key.mv_data = (char*)"schemaversion";
  key.mv_size = strlen((char*)key.mv_data);

  if ((rc = mdb_get(txn, dbi, &key, &data)) != 0) {
    if (rc == MDB_NOTFOUND) {
      // this means nothing has been inited yet
      // we pretend this means 5
      mdb_txn_abort(txn);
      mdb_env_close(env);
      return {5u, 0u};
    }

    throw std::runtime_error("mdb_get pdns.schemaversion failed");
  }

  if (data.mv_size == 4) {
    // schemaversion is < 5 and is stored in 32 bits, in host order

    memcpy(&schemaversion, data.mv_data, data.mv_size);
  }
  else if (data.mv_size >= LMDBLS::LS_MIN_HEADER_SIZE + sizeof(schemaversion)) {
    // schemaversion presumably is 5, stored in 32 bits, network order, after the LS header

    // FIXME: get actual header size (including extension blocks) instead of just reading from the back
    // FIXME: add a test for reading schemaversion and shards (and actual data, later) when there are variably sized headers
    memcpy(&schemaversion, (char*)data.mv_data + data.mv_size - sizeof(schemaversion), sizeof(schemaversion));
    schemaversion = ntohl(schemaversion);
  }
  else {
    throw std::runtime_error("pdns.schemaversion had unexpected size");
  }

  uint32_t shards;

  key.mv_data = (char*)"shards";
  key.mv_size = strlen((char*)key.mv_data);

  if ((rc = mdb_get(txn, dbi, &key, &data)) != 0) {
    if (rc == MDB_NOTFOUND) {
      cerr << "schemaversion was set, but shards was not. Dazed and confused, trying to exit." << endl;
      mdb_txn_abort(txn);
      mdb_env_close(env);
      exit(1);
    }

    throw std::runtime_error("mdb_get pdns.shards failed");
  }

  if (data.mv_size == 4) {
    // 'shards' is stored in 32 bits, in host order

    memcpy(&shards, data.mv_data, data.mv_size);
  }
  else if (data.mv_size >= LMDBLS::LS_MIN_HEADER_SIZE + sizeof(shards)) {
    // FIXME: get actual header size (including extension blocks) instead of just reading from the back
    memcpy(&shards, (char*)data.mv_data + data.mv_size - sizeof(shards), sizeof(shards));
    shards = ntohl(shards);
  }
  else {
    throw std::runtime_error("pdns.shards had unexpected size");
  }

  mdb_txn_abort(txn);
  mdb_env_close(env);

  return {schemaversion, shards};
}

namespace
{
// copy sdbi to tdbi, prepending an empty LS header (24 bytes of '\0') to all values
void copyDBIAndAddLSHeader(MDB_txn* txn, MDB_dbi sdbi, MDB_dbi tdbi)
{
  // FIXME: clear out target dbi first

  std::string header(LMDBLS::LS_MIN_HEADER_SIZE, '\0');
  int rc;

  MDB_cursor* cur;

  if ((rc = mdb_cursor_open(txn, sdbi, &cur)) != 0) {
    throw std::runtime_error("mdb_cursur_open failed");
  }

  MDB_val key, data;

  rc = mdb_cursor_get(cur, &key, &data, MDB_FIRST);

  while (rc == 0) {
    std::string skey(reinterpret_cast<const char*>(key.mv_data), key.mv_size);
    std::string sdata(reinterpret_cast<const char*>(data.mv_data), data.mv_size);

    std::string stdata = header + sdata;

    // cerr<<"got key="<<makeHexDump(skey)<<", data="<<makeHexDump(sdata)<<", sdata="<<makeHexDump(stdata)<<endl;

    MDB_val tkey;
    MDB_val tdata;

    tkey.mv_data = const_cast<char*>(skey.c_str());
    tkey.mv_size = skey.size();
    tdata.mv_data = const_cast<char*>(stdata.c_str());
    tdata.mv_size = stdata.size();

    if ((rc = mdb_put(txn, tdbi, &tkey, &tdata, 0)) != 0) {
      throw std::runtime_error("mdb_put failed");
    }

    rc = mdb_cursor_get(cur, &key, &data, MDB_NEXT);
  }
  if (rc != MDB_NOTFOUND) {
    cerr << "rc=" << rc << endl;
    throw std::runtime_error("error while iterating dbi");
  }
}

// migrated a typed DBI:
// 1. change keys (uint32_t) from host to network order
// 2. prepend empty LS header to values
void copyTypedDBI(MDB_txn* txn, MDB_dbi sdbi, MDB_dbi tdbi)
{
  // FIXME: clear out target dbi first

  std::string header(LMDBLS::LS_MIN_HEADER_SIZE, '\0');
  int rc;

  MDB_cursor* cur;

  if ((rc = mdb_cursor_open(txn, sdbi, &cur)) != 0) {
    throw std::runtime_error("mdb_cursur_open failed");
  }

  MDB_val key, data;

  rc = mdb_cursor_get(cur, &key, &data, MDB_FIRST);

  while (rc == 0) {
    // std::string skey((char*) key.mv_data, key.mv_size);
    std::string sdata(reinterpret_cast<const char*>(data.mv_data), data.mv_size);

    std::string stdata = header + sdata;

    uint32_t id;

    if (key.mv_size != sizeof(uint32_t)) {
      throw std::runtime_error("got non-uint32_t key in TypedDBI");
    }

    memcpy(&id, key.mv_data, sizeof(uint32_t));

    id = htonl(id);

    // cerr<<"got key="<<makeHexDump(skey)<<", data="<<makeHexDump(sdata)<<", sdata="<<makeHexDump(stdata)<<endl;

    MDB_val tkey;
    MDB_val tdata;

    tkey.mv_data = reinterpret_cast<char*>(&id);
    tkey.mv_size = sizeof(uint32_t);
    tdata.mv_data = const_cast<char*>(stdata.c_str());
    tdata.mv_size = stdata.size();

    if ((rc = mdb_put(txn, tdbi, &tkey, &tdata, 0)) != 0) {
      throw std::runtime_error("mdb_put failed");
    }

    rc = mdb_cursor_get(cur, &key, &data, MDB_NEXT);
  }
  if (rc != MDB_NOTFOUND) {
    cerr << "rc=" << rc << endl;
    throw std::runtime_error("error while iterating dbi");
  }
}

// migrating an index DBI:
// newkey = oldkey.len(), oldkey, htonl(oldvalue)
// newvalue = empty lsheader
void copyIndexDBI(MDB_txn* txn, MDB_dbi sdbi, MDB_dbi tdbi)
{
  // FIXME: clear out target dbi first

  std::string header(LMDBLS::LS_MIN_HEADER_SIZE, '\0');
  int rc;

  MDB_cursor* cur;

  if ((rc = mdb_cursor_open(txn, sdbi, &cur)) != 0) {
    throw std::runtime_error("mdb_cursur_open failed");
  }

  MDB_val key, data;

  rc = mdb_cursor_get(cur, &key, &data, MDB_FIRST);

  while (rc == 0) {
    std::string lenprefix(sizeof(uint16_t), '\0');
    std::string skey((char*)key.mv_data, key.mv_size);

    uint32_t id;

    if (data.mv_size != sizeof(uint32_t)) {
      throw std::runtime_error("got non-uint32_t ID value in IndexDBI");
    }

    memcpy((void*)&id, data.mv_data, sizeof(uint32_t));
    id = htonl(id);

    uint16_t len = htons(skey.size());
    memcpy((void*)lenprefix.data(), &len, sizeof(len));
    std::string stkey = lenprefix + skey + std::string((char*)&id, sizeof(uint32_t));

    MDB_val tkey;
    MDB_val tdata;

    tkey.mv_data = (char*)stkey.c_str();
    tkey.mv_size = stkey.size();
    tdata.mv_data = (char*)header.c_str();
    tdata.mv_size = header.size();

    if ((rc = mdb_put(txn, tdbi, &tkey, &tdata, 0)) != 0) {
      throw std::runtime_error("mdb_put failed");
    }

    rc = mdb_cursor_get(cur, &key, &data, MDB_NEXT);
  }
  if (rc != MDB_NOTFOUND) {
    throw std::runtime_error("error while iterating dbi");
  }
}

}

bool LMDBBackend::upgradeToSchemav5(std::string& filename)
{
  int rc;

  auto currentSchemaVersionAndShards = getSchemaVersionAndShards(filename);
  uint32_t currentSchemaVersion = currentSchemaVersionAndShards.first;
  uint32_t shards = currentSchemaVersionAndShards.second;

  if (currentSchemaVersion != 3 && currentSchemaVersion != 4) {
    throw std::runtime_error("upgrade to v5 requested but current schema is not v3 or v4, stopping");
  }

  MDB_env* env = nullptr;

  if ((rc = mdb_env_create(&env)) != 0) {
    throw std::runtime_error("mdb_env_create failed");
  }

  if ((rc = mdb_env_set_maxdbs(env, 20)) != 0) {
    mdb_env_close(env);
    throw std::runtime_error("mdb_env_set_maxdbs failed");
  }

  if ((rc = mdb_env_open(env, filename.c_str(), MDB_NOSUBDIR, 0600)) != 0) {
    mdb_env_close(env);
    throw std::runtime_error("mdb_env_open failed");
  }

  MDB_txn* txn = nullptr;

  if ((rc = mdb_txn_begin(env, NULL, 0, &txn)) != 0) {
    mdb_env_close(env);
    throw std::runtime_error("mdb_txn_begin failed");
  }

#ifdef HAVE_SYSTEMD
  /* A schema migration may take a long time. Extend the startup service timeout to 1 day,
   * but only if this is beyond the original maximum time of TimeoutStartSec=.
   */
  sd_notify(0, "EXTEND_TIMEOUT_USEC=86400000000");
#endif

  std::cerr << "migrating shards" << std::endl;
  for (uint32_t i = 0; i < shards; i++) {
    string shardfile = filename + "-" + std::to_string(i);
    if (access(shardfile.c_str(), F_OK) < 0) {
      if (errno == ENOENT) {
        // apparently this shard doesn't exist yet, moving on
        std::cerr << "shard " << shardfile << " not found, continuing" << std::endl;
        continue;
      }
    }

    std::cerr << "migrating shard " << shardfile << std::endl;
    MDB_env* shenv = nullptr;

    if ((rc = mdb_env_create(&shenv)) != 0) {
      throw std::runtime_error("mdb_env_create failed");
    }

    if ((rc = mdb_env_set_maxdbs(shenv, 8)) != 0) {
      mdb_env_close(env);
      throw std::runtime_error("mdb_env_set_maxdbs failed");
    }

    if ((rc = mdb_env_open(shenv, shardfile.c_str(), MDB_NOSUBDIR, 0600)) != 0) {
      mdb_env_close(env);
      throw std::runtime_error("mdb_env_open failed");
    }

    MDB_txn* shtxn = nullptr;

    if ((rc = mdb_txn_begin(shenv, NULL, 0, &shtxn)) != 0) {
      mdb_env_close(env);
      throw std::runtime_error("mdb_txn_begin failed");
    }

    MDB_dbi shdbi;

    if ((rc = mdb_dbi_open(shtxn, "records", 0, &shdbi)) != 0) {
      if (rc == MDB_NOTFOUND) {
        mdb_txn_abort(shtxn);
        mdb_env_close(shenv);
        continue;
      }
      mdb_txn_abort(shtxn);
      mdb_env_close(shenv);
      throw std::runtime_error("mdb_dbi_open shard records failed");
    }

    MDB_dbi shdbi2;

    if ((rc = mdb_dbi_open(shtxn, "records_v5", MDB_CREATE, &shdbi2)) != 0) {
      mdb_dbi_close(shenv, shdbi);
      mdb_txn_abort(shtxn);
      mdb_env_close(shenv);
      throw std::runtime_error("mdb_dbi_open shard records_v5 failed");
    }

    try {
      copyDBIAndAddLSHeader(shtxn, shdbi, shdbi2);
    }
    catch (std::exception& e) {
      mdb_dbi_close(shenv, shdbi2);
      mdb_dbi_close(shenv, shdbi);
      mdb_txn_abort(shtxn);
      mdb_env_close(shenv);
      throw std::runtime_error("copyDBIAndAddLSHeader failed");
    }

    cerr << "shard mbd_drop=" << mdb_drop(shtxn, shdbi, 1) << endl;
    mdb_txn_commit(shtxn);
    mdb_dbi_close(shenv, shdbi2);
    mdb_env_close(shenv);
  }

  std::array<MDB_dbi, 4> fromtypeddbi;
  std::array<MDB_dbi, 4> totypeddbi;

  int index = 0;

  for (const std::string dbname : {"domains", "keydata", "tsig", "metadata"}) {
    std::cerr << "migrating " << dbname << std::endl;
    std::string tdbname = dbname + "_v5";

    if ((rc = mdb_dbi_open(txn, dbname.c_str(), 0, &fromtypeddbi[index])) != 0) {
      mdb_txn_abort(txn);
      mdb_env_close(env);
      throw std::runtime_error("mdb_dbi_open typeddbi failed");
    }

    if ((rc = mdb_dbi_open(txn, tdbname.c_str(), MDB_CREATE, &totypeddbi[index])) != 0) {
      mdb_dbi_close(env, fromtypeddbi[index]);
      mdb_txn_abort(txn);
      mdb_env_close(env);
      throw std::runtime_error("mdb_dbi_open typeddbi target failed");
    }

    try {
      copyTypedDBI(txn, fromtypeddbi[index], totypeddbi[index]);
    }
    catch (std::exception& e) {
      mdb_dbi_close(env, totypeddbi[index]);
      mdb_dbi_close(env, fromtypeddbi[index]);
      mdb_txn_abort(txn);
      mdb_env_close(env);
      throw std::runtime_error("copyTypedDBI failed");
    }

    // mdb_dbi_close(env, dbi2);
    // mdb_dbi_close(env, dbi);
    std::cerr << "migrated " << dbname << std::endl;

    index++;
  }

  std::array<MDB_dbi, 4> fromindexdbi;
  std::array<MDB_dbi, 4> toindexdbi;

  index = 0;

  for (const std::string dbname : {"domains", "keydata", "tsig", "metadata"}) {
    std::string fdbname = dbname + "_0";
    std::cerr << "migrating " << dbname << std::endl;
    std::string tdbname = dbname + "_v5_0";

    if ((rc = mdb_dbi_open(txn, fdbname.c_str(), 0, &fromindexdbi[index])) != 0) {
      mdb_txn_abort(txn);
      mdb_env_close(env);
      throw std::runtime_error("mdb_dbi_open indexdbi failed");
    }

    if ((rc = mdb_dbi_open(txn, tdbname.c_str(), MDB_CREATE, &toindexdbi[index])) != 0) {
      mdb_dbi_close(env, fromindexdbi[index]);
      mdb_txn_abort(txn);
      mdb_env_close(env);
      throw std::runtime_error("mdb_dbi_open indexdbi target failed");
    }

    try {
      copyIndexDBI(txn, fromindexdbi[index], toindexdbi[index]);
    }
    catch (std::exception& e) {
      mdb_dbi_close(env, toindexdbi[index]);
      mdb_dbi_close(env, fromindexdbi[index]);
      mdb_txn_abort(txn);
      mdb_env_close(env);
      throw std::runtime_error("copyIndexDBI failed");
    }

    // mdb_dbi_close(env, dbi2);
    // mdb_dbi_close(env, dbi);
    std::cerr << "migrated " << dbname << std::endl;

    index++;
  }

  MDB_dbi dbi;

  // finally, migrate the pdns db
  if ((rc = mdb_dbi_open(txn, "pdns", 0, &dbi)) != 0) {
    mdb_txn_abort(txn);
    mdb_env_close(env);
    throw std::runtime_error("mdb_dbi_open pdns failed");
  }

  MDB_val key, data;

  std::string header(LMDBLS::LS_MIN_HEADER_SIZE, '\0');

  for (const std::string keyname : {"schemaversion", "shards"}) {
    cerr << "migrating pdns." << keyname << endl;

    key.mv_data = (char*)keyname.c_str();
    key.mv_size = keyname.size();

    if ((rc = mdb_get(txn, dbi, &key, &data))) {
      throw std::runtime_error("mdb_get pdns.shards failed");
    }

    uint32_t value;

    if (data.mv_size != sizeof(uint32_t)) {
      throw std::runtime_error("got non-uint32_t key");
    }

    memcpy((void*)&value, data.mv_data, sizeof(uint32_t));

    value = htonl(value);
    if (keyname == "schemaversion") {
      value = htonl(5);
    }

    std::string sdata((char*)data.mv_data, data.mv_size);

    std::string stdata = header + std::string((char*)&value, sizeof(uint32_t));
    ;

    MDB_val tdata;

    tdata.mv_data = (char*)stdata.c_str();
    tdata.mv_size = stdata.size();

    if ((rc = mdb_put(txn, dbi, &key, &tdata, 0)) != 0) {
      throw std::runtime_error("mdb_put failed");
    }
  }

  for (const std::string keyname : {"uuid"}) {
    cerr << "migrating pdns." << keyname << endl;

    key.mv_data = (char*)keyname.c_str();
    key.mv_size = keyname.size();

    if ((rc = mdb_get(txn, dbi, &key, &data))) {
      throw std::runtime_error("mdb_get pdns.shards failed");
    }

    std::string sdata((char*)data.mv_data, data.mv_size);

    std::string stdata = header + sdata;

    MDB_val tdata;

    tdata.mv_data = (char*)stdata.c_str();
    tdata.mv_size = stdata.size();

    if ((rc = mdb_put(txn, dbi, &key, &tdata, 0)) != 0) {
      throw std::runtime_error("mdb_put failed");
    }
  }

  for (int i = 0; i < 4; i++) {
    mdb_drop(txn, fromtypeddbi[i], 1);
    mdb_drop(txn, fromindexdbi[i], 1);
  }

  cerr << "txn commit=" << mdb_txn_commit(txn) << endl;

  for (int i = 0; i < 4; i++) {
    mdb_dbi_close(env, totypeddbi[i]);
    mdb_dbi_close(env, toindexdbi[i]);
  }
  mdb_env_close(env);

  // throw std::runtime_error("migration done");
  cerr << "migration done" << endl;
  // exit(1);
  return true;
}

// Serial number cache

// Retrieve the transient domain info for the given domain, if any
bool LMDBBackend::TransientDomainInfoCache::get(uint32_t domainid, TransientDomainInfo& data) const
{
  if (auto iter = d_data.find(domainid); iter != d_data.end()) {
    data = iter->second;
    return true;
  }
  return false;
}

// Remove the transient domain info for the given domain
void LMDBBackend::TransientDomainInfoCache::remove(uint32_t domainid)
{
  if (auto iter = d_data.find(domainid); iter != d_data.end()) {
    d_data.erase(iter);
  }
}

// Create or update the transient domain info for the given domain
void LMDBBackend::TransientDomainInfoCache::update(uint32_t domainid, const TransientDomainInfo& data)
{
  d_data.insert_or_assign(domainid, data);
}

SharedLockGuarded<LMDBBackend::TransientDomainInfoCache> LMDBBackend::s_transient_domain_info;

LMDBBackend::LMDBBackend(const std::string& suffix)
{
  // overlapping domain ids in combination with relative names are a recipe for disaster
  if (!suffix.empty()) {
    throw std::runtime_error("LMDB backend does not support multiple instances");
  }

  setArgPrefix("lmdb" + suffix);

  string syncMode = toLower(getArg("sync-mode"));

  if (syncMode == "nosync")
    d_asyncFlag = MDB_NOSYNC;
  else if (syncMode == "nometasync")
    d_asyncFlag = MDB_NOMETASYNC;
  else if (syncMode.empty() || syncMode == "sync")
    d_asyncFlag = 0;
  else
    throw std::runtime_error("Unknown sync mode " + syncMode + " requested for LMDB backend");

  d_mapsize = 0;
  try {
    d_mapsize = std::stoll(getArg("map-size"));
  }
  catch (const std::exception& e) {
    throw std::runtime_error(std::string("Unable to parse the 'map-size' LMDB value: ") + e.what());
  }

  d_write_notification_update = mustDo("write-notification-update");

  if (mustDo("lightning-stream")) {
    d_random_ids = true;
    d_handle_dups = true;
    LMDBLS::s_flag_deleted = true;

    if (atoi(getArg("shards").c_str()) != 1) {
      throw std::runtime_error(std::string("running with Lightning Stream support requires shards=1"));
    }
  }
  else {
    d_random_ids = mustDo("random-ids");
    d_handle_dups = false;
    LMDBLS::s_flag_deleted = mustDo("flag-deleted");
  }

  bool opened = false;

  if (s_first) {
    std::lock_guard<std::mutex> l(s_lmdbStartupLock);
    if (s_first) {
      auto filename = getArg("filename");

      auto currentSchemaVersionAndShards = getSchemaVersionAndShards(filename);
      uint32_t currentSchemaVersion = currentSchemaVersionAndShards.first;
      // std::cerr<<"current schema version: "<<currentSchemaVersion<<", shards="<<currentSchemaVersionAndShards.second<<std::endl;

      if (getArgAsNum("schema-version") != SCHEMAVERSION) {
        throw std::runtime_error("This version of the lmdbbackend only supports schema version 5. Configuration demands a lower version. Not starting up.");
      }

      if (currentSchemaVersion > 0 && currentSchemaVersion < 3) {
        throw std::runtime_error("this version of the lmdbbackend can only upgrade from schema v3/v4 to v5. Upgrading from older schemas is not yet supported.");
      }

      if (currentSchemaVersion == 0) {
        // no database is present yet, we can just create them
        currentSchemaVersion = 5;
      }

      if (currentSchemaVersion == 3 || currentSchemaVersion == 4) {
        if (!upgradeToSchemav5(filename)) {
          throw std::runtime_error("Failed to perform LMDB schema version upgrade from v4 to v5");
        }
        currentSchemaVersion = 5;
      }

      if (currentSchemaVersion != 5) {
        throw std::runtime_error("Somehow, we are not at schema version 5. Giving up");
      }

      d_tdomains = std::make_shared<tdomains_t>(getMDBEnv(getArg("filename").c_str(), MDB_NOSUBDIR | d_asyncFlag, 0600, d_mapsize), "domains_v5");
      d_tmeta = std::make_shared<tmeta_t>(d_tdomains->getEnv(), "metadata_v5");
      d_tkdb = std::make_shared<tkdb_t>(d_tdomains->getEnv(), "keydata_v5");
      d_ttsig = std::make_shared<ttsig_t>(d_tdomains->getEnv(), "tsig_v5");

      auto pdnsdbi = d_tdomains->getEnv()->openDB("pdns", MDB_CREATE);

      opened = true;

      auto txn = d_tdomains->getEnv()->getRWTransaction();

      MDBOutVal shards;
      if (!txn->get(pdnsdbi, "shards", shards)) {
        s_shards = shards.get<uint32_t>();

        if (mustDo("lightning-stream") && s_shards != 1) {
          throw std::runtime_error(std::string("running with Lightning Stream support enabled requires a database with exactly 1 shard"));
        }

        if (s_shards != atoi(getArg("shards").c_str())) {
          g_log << Logger::Warning << "Note: configured number of lmdb shards (" << atoi(getArg("shards").c_str()) << ") is different from on-disk (" << s_shards << "). Using on-disk shard number" << endl;
        }
      }
      else {
        s_shards = atoi(getArg("shards").c_str());
        txn->put(pdnsdbi, "shards", s_shards);
      }

      MDBOutVal gotuuid;
      if (txn->get(pdnsdbi, "uuid", gotuuid)) {
        const auto uuid = getUniqueID();
        const string uuids(uuid.begin(), uuid.end());
        txn->put(pdnsdbi, "uuid", uuids);
      }

      MDBOutVal _schemaversion;
      if (txn->get(pdnsdbi, "schemaversion", _schemaversion)) {
        // our DB is entirely new, so we need to write the schemaversion
        txn->put(pdnsdbi, "schemaversion", currentSchemaVersion);
      }
      txn->commit();

      s_first = false;
    }
  }

  if (!opened) {
    d_tdomains = std::make_shared<tdomains_t>(getMDBEnv(getArg("filename").c_str(), MDB_NOSUBDIR | d_asyncFlag, 0600, d_mapsize), "domains_v5");
    d_tmeta = std::make_shared<tmeta_t>(d_tdomains->getEnv(), "metadata_v5");
    d_tkdb = std::make_shared<tkdb_t>(d_tdomains->getEnv(), "keydata_v5");
    d_ttsig = std::make_shared<ttsig_t>(d_tdomains->getEnv(), "tsig_v5");
  }
  d_trecords.resize(s_shards);
  d_dolog = ::arg().mustDo("query-logging");
}

namespace boost
{
namespace serialization
{

  template <class Archive>
  void save(Archive& ar, const DNSName& g, const unsigned int /* version */)
  {
    if (g.empty()) {
      ar& std::string();
    }
    else {
      ar& g.toDNSStringLC();
    }
  }

  template <class Archive>
  void load(Archive& ar, DNSName& g, const unsigned int /* version */)
  {
    string tmp;
    ar& tmp;
    if (tmp.empty()) {
      g = DNSName();
    }
    else {
      g = DNSName(tmp.c_str(), tmp.size(), 0, false);
    }
  }

  template <class Archive>
  void save(Archive& ar, const QType& g, const unsigned int /* version */)
  {
    ar& g.getCode();
  }

  template <class Archive>
  void load(Archive& ar, QType& g, const unsigned int /* version */)
  {
    uint16_t tmp;
    ar& tmp;
    g = QType(tmp);
  }

  template <class Archive>
  void save(Archive& ar, const DomainInfo& g, const unsigned int /* version */)
  {
    ar& g.zone;
    ar& g.last_check;
    ar& g.account;
    ar& g.primaries;
    ar& g.id;
    ar& g.notified_serial;
    ar& g.kind;
    ar& g.options;
    ar& g.catalog;
  }

  template <class Archive>
  void load(Archive& ar, DomainInfo& g, const unsigned int version)
  {
    ar& g.zone;
    ar& g.last_check;
    ar& g.account;
    ar& g.primaries;
    ar& g.id;
    ar& g.notified_serial;
    ar& g.kind;
    if (version >= 1) {
      ar& g.options;
      ar& g.catalog;
    }
    else {
      g.options.clear();
      g.catalog.clear();
    }
  }

  template <class Archive>
  void serialize(Archive& ar, LMDBBackend::DomainMeta& g, const unsigned int /* version */)
  {
    ar& g.domain& g.key& g.value;
  }

  template <class Archive>
  void save(Archive& ar, const LMDBBackend::KeyDataDB& g, const unsigned int /* version */)
  {
    ar& g.domain& g.content& g.flags& g.active& g.published;
  }

  template <class Archive>
  void load(Archive& ar, LMDBBackend::KeyDataDB& g, const unsigned int version)
  {
    ar& g.domain& g.content& g.flags& g.active;
    if (version >= 1) {
      ar& g.published;
    }
    else {
      g.published = true;
    }
  }

  template <class Archive>
  void serialize(Archive& ar, TSIGKey& g, const unsigned int /* version */)
  {
    ar& g.name;
    ar& g.algorithm; // this is the ordername
    ar& g.key;
  }

} // namespace serialization
} // namespace boost

BOOST_SERIALIZATION_SPLIT_FREE(DNSName);
BOOST_SERIALIZATION_SPLIT_FREE(QType);
BOOST_SERIALIZATION_SPLIT_FREE(LMDBBackend::KeyDataDB);
BOOST_SERIALIZATION_SPLIT_FREE(DomainInfo);
BOOST_IS_BITWISE_SERIALIZABLE(ComboAddress);

template <>
std::string serToString(const LMDBBackend::LMDBResourceRecord& lrr)
{
  std::string ret;
  uint16_t len = lrr.content.length();
  ret.reserve(2 + len + 7);

  ret.assign((const char*)&len, 2);
  ret += lrr.content;
  ret.append((const char*)&lrr.ttl, 4);
  ret.append(1, (char)lrr.auth);
  ret.append(1, (char)lrr.disabled);
  ret.append(1, (char)lrr.ordername);
  return ret;
}

template <>
std::string serToString(const vector<LMDBBackend::LMDBResourceRecord>& lrrs)
{
  std::string ret;
  for (const auto& lrr : lrrs) {
    ret += serToString(lrr);
  }
  return ret;
}

static inline size_t serOneRRFromString(const string_view& str, LMDBBackend::LMDBResourceRecord& lrr)
{
  uint16_t len;
  memcpy(&len, &str[0], 2);
  lrr.content.assign(&str[2], len); // len bytes
  memcpy(&lrr.ttl, &str[2] + len, 4);
  lrr.auth = str[2 + len + 4];
  lrr.disabled = str[2 + len + 4 + 1];
  lrr.ordername = str[2 + len + 4 + 2];
  lrr.wildcardname.clear();

  return 2 + len + 7;
}

template <>
void serFromString(const string_view& str, LMDBBackend::LMDBResourceRecord& lrr)
{
  serOneRRFromString(str, lrr);
}

template <>
void serFromString(const string_view& str, vector<LMDBBackend::LMDBResourceRecord>& lrrs)
{
  auto str_copy = str;
  while (str_copy.size() >= 9) { // minimum length for a record is 10
    LMDBBackend::LMDBResourceRecord lrr;
    auto rrLength = serOneRRFromString(str_copy, lrr);
    lrrs.emplace_back(lrr);
    str_copy.remove_prefix(rrLength);
  }
}

static std::string serializeContent(uint16_t qtype, const DNSName& domain, const std::string& content)
{
  auto drc = DNSRecordContent::make(qtype, QClass::IN, content);
  return drc->serialize(domain, false);
}

static std::shared_ptr<DNSRecordContent> deserializeContentZR(uint16_t qtype, const DNSName& qname, const std::string& content)
{
  if (qtype == QType::A && content.size() == 4) {
    return std::make_shared<ARecordContent>(*((uint32_t*)content.c_str()));
  }
  return DNSRecordContent::deserialize(qname, qtype, content);
}

/* design. If you ask a question without a zone id, we lookup the best
   zone id for you, and answer from that. This is different than other backends, but I can't see why it would not work.

   The index we use is "zoneid,canonical relative name". This index is also used
   for AXFR.

   Note - domain_id, name and type are ONLY present on the index!
*/

#if BOOST_VERSION >= 106100
#define StringView string_view
#else
#define StringView string
#endif

void LMDBBackend::deleteDomainRecords(RecordsRWTransaction& txn, uint32_t domain_id, uint16_t qtype)
{
  compoundOrdername co;
  string match = co(domain_id);

  auto cursor = txn.txn->getCursor(txn.db->dbi);
  MDBOutVal key, val;
  //  cout<<"Match: "<<makeHexDump(match);
  if (!cursor.lower_bound(match, key, val)) {
    while (key.getNoStripHeader<StringView>().rfind(match, 0) == 0) {
      if (qtype == QType::ANY || co.getQType(key.getNoStripHeader<StringView>()) == qtype)
        cursor.del();
      if (cursor.next(key, val))
        break;
    }
  }
}

bool LMDBBackend::findDomain(const DNSName& domain, DomainInfo& info) const
{
  auto rotxn = d_tdomains->getROTransaction();
  auto domain_id = rotxn.get<0>(domain, info);
  if (domain_id == 0) {
    return false;
  }
  info.id = static_cast<uint32_t>(domain_id);
  return true;
}

bool LMDBBackend::findDomain(uint32_t domainid, DomainInfo& info) const
{
  auto rotxn = d_tdomains->getROTransaction();
  if (!rotxn.get(domainid, info)) {
    return false;
  }
  info.id = domainid;
  return true;
}

void LMDBBackend::consolidateDomainInfo(DomainInfo& info) const
{
  // Update the notified_serial value if we have a cached value in memory.
  if (!d_write_notification_update) {
    auto container = s_transient_domain_info.read_lock();
    TransientDomainInfo tdi;
    container->get(info.id, tdi);
    info.notified_serial = tdi.notified_serial;
    info.last_check = tdi.last_check;
  }
}

void LMDBBackend::writeDomainInfo(const DomainInfo& info)
{
  if (!d_write_notification_update) {
    auto container = s_transient_domain_info.write_lock();
    TransientDomainInfo tdi;
    container->get(info.id, tdi);
    // Only remove the in-memory value if it has not been modified since the
    // DomainInfo data was set up.
    if (tdi.notified_serial == info.notified_serial && tdi.last_check == info.last_check) {
      container->remove(info.id);
    }
  }
  auto txn = d_tdomains->getRWTransaction();
  txn.put(info, info.id);
  txn.commit();
}

/* Here's the complicated story. Other backends have just one transaction, which is either
   on or not.

   You can't call feedRecord without a transaction started with startTransaction.

   However, other functions can be called after startTransaction() or without startTransaction()
     (like updateDNSSECOrderNameAndAuth)



*/

bool LMDBBackend::startTransaction(const DNSName& domain, int domain_id)
{
  // cout <<"startTransaction("<<domain<<", "<<domain_id<<")"<<endl;
  int real_id = domain_id;
  if (real_id < 0) {
    DomainInfo info;
    if (!findDomain(domain, info)) {
      return false;
    }
    real_id = static_cast<int>(info.id);
  }
  if (d_rwtxn) {
    throw DBException("Attempt to start a transaction while one was open already");
  }
  d_rwtxn = getRecordsRWTransaction(real_id);

  d_transactiondomain = domain;
  d_transactiondomainid = real_id;
  if (domain_id >= 0) {
    deleteDomainRecords(*d_rwtxn, domain_id);
  }

  return true;
}

bool LMDBBackend::commitTransaction()
{
  // cout<<"Commit transaction" <<endl;
  if (!d_rwtxn) {
    throw DBException("Attempt to commit a transaction while there isn't one open");
  }

  d_rwtxn->txn->commit();
  d_rwtxn.reset();
  return true;
}

bool LMDBBackend::abortTransaction()
{
  // cout<<"Abort transaction"<<endl;
  if (!d_rwtxn) {
    throw DBException("Attempt to abort a transaction while there isn't one open");
  }

  d_rwtxn->txn->abort();
  d_rwtxn.reset();

  return true;
}

// d_rwtxn must be set here
bool LMDBBackend::feedRecord(const DNSResourceRecord& r, const DNSName& ordername, bool ordernameIsNSEC3)
{
  LMDBResourceRecord lrr(r);
  lrr.qname.makeUsRelative(d_transactiondomain);
  lrr.content = serializeContent(lrr.qtype.getCode(), r.qname, lrr.content);

  compoundOrdername co;
  string matchName = co(lrr.domain_id, lrr.qname, lrr.qtype.getCode());

  string rrs;
  MDBOutVal _rrs;
  if (!d_rwtxn->txn->get(d_rwtxn->db->dbi, matchName, _rrs)) {
    rrs = _rrs.get<string>();
  }

  rrs += serToString(lrr);

  d_rwtxn->txn->put(d_rwtxn->db->dbi, matchName, rrs);

  if (ordernameIsNSEC3 && !ordername.empty()) {
    MDBOutVal val;
    if (d_rwtxn->txn->get(d_rwtxn->db->dbi, co(lrr.domain_id, lrr.qname, QType::NSEC3), val)) {
      lrr.ttl = 0;
      lrr.content = lrr.qname.toDNSStringLC();
      lrr.auth = 0;
      string ser = serToString(lrr);
      d_rwtxn->txn->put(d_rwtxn->db->dbi, co(lrr.domain_id, ordername, QType::NSEC3), ser);

      lrr.ttl = 1;
      lrr.content = ordername.toDNSString();
      ser = serToString(lrr);
      d_rwtxn->txn->put(d_rwtxn->db->dbi, co(lrr.domain_id, lrr.qname, QType::NSEC3), ser);
    }
  }
  return true;
}

bool LMDBBackend::feedEnts(int domain_id, map<DNSName, bool>& nonterm)
{
  LMDBResourceRecord lrr;
  lrr.ttl = 0;
  compoundOrdername co;
  for (const auto& nt : nonterm) {
    lrr.qname = nt.first.makeRelative(d_transactiondomain);
    lrr.auth = nt.second;
    lrr.ordername = true;

    std::string ser = serToString(lrr);
    d_rwtxn->txn->put(d_rwtxn->db->dbi, co(domain_id, lrr.qname, QType::ENT), ser);
  }
  return true;
}

bool LMDBBackend::feedEnts3(int domain_id, const DNSName& domain, map<DNSName, bool>& nonterm, const NSEC3PARAMRecordContent& ns3prc, bool narrow)
{
  string ser;
  DNSName ordername;
  LMDBResourceRecord lrr;
  compoundOrdername co;
  for (const auto& nt : nonterm) {
    lrr.qname = nt.first.makeRelative(domain);
    lrr.ttl = 0;
    lrr.auth = nt.second;
    lrr.ordername = nt.second;
    ser = serToString(lrr);
    d_rwtxn->txn->put(d_rwtxn->db->dbi, co(domain_id, lrr.qname, QType::ENT), ser);

    if (!narrow && lrr.auth) {
      lrr.content = lrr.qname.toDNSString();
      lrr.auth = false;
      lrr.ordername = false;
      ser = serToString(lrr);

      ordername = DNSName(toBase32Hex(hashQNameWithSalt(ns3prc, nt.first)));
      d_rwtxn->txn->put(d_rwtxn->db->dbi, co(domain_id, ordername, QType::NSEC3), ser);

      lrr.ttl = 1;
      lrr.content = ordername.toDNSString();
      ser = serToString(lrr);
      d_rwtxn->txn->put(d_rwtxn->db->dbi, co(domain_id, lrr.qname, QType::NSEC3), ser);
    }
  }
  return true;
}

// might be called within a transaction, might also be called alone
bool LMDBBackend::replaceRRSet(uint32_t domain_id, const DNSName& qname, const QType& qt, const vector<DNSResourceRecord>& rrset)
{
  // zonk qname/qtype within domain_id (go through qname, check domain_id && qtype)
  shared_ptr<RecordsRWTransaction> txn;
  bool needCommit = false;
  if (d_rwtxn && d_transactiondomainid == domain_id) {
    txn = d_rwtxn;
    //    cout<<"Reusing open transaction"<<endl;
  }
  else {
    //    cout<<"Making a new RW txn for replace rrset"<<endl;
    txn = getRecordsRWTransaction(domain_id);
    needCommit = true;
  }

  DomainInfo info;
  if (!findDomain(domain_id, info)) {
    return false;
  }

  compoundOrdername co;
  auto cursor = txn->txn->getCursor(txn->db->dbi);
  MDBOutVal key, val;
  string match = co(domain_id, qname.makeRelative(info.zone), qt.getCode());
  if (!cursor.find(match, key, val)) {
    cursor.del();
  }

  if (!rrset.empty()) {
    vector<LMDBResourceRecord> adjustedRRSet;
    for (const auto& rr : rrset) {
      LMDBResourceRecord lrr(rr);
      lrr.content = serializeContent(lrr.qtype.getCode(), lrr.qname, lrr.content);
      lrr.qname.makeUsRelative(info.zone);

      adjustedRRSet.emplace_back(lrr);
    }
    txn->txn->put(txn->db->dbi, match, serToString(adjustedRRSet));
  }

  if (needCommit)
    txn->txn->commit();

  return true;
}

bool LMDBBackend::replaceComments([[maybe_unused]] const uint32_t domain_id, [[maybe_unused]] const DNSName& qname, [[maybe_unused]] const QType& qt, const vector<Comment>& comments)
{
  // if the vector is empty, good, that's what we do here (LMDB does not store comments)
  // if it's not, report failure
  return comments.empty();
}

// tempting to templatize these two functions but the pain is not worth it
std::shared_ptr<LMDBBackend::RecordsRWTransaction> LMDBBackend::getRecordsRWTransaction(uint32_t id)
{
  auto& shard = d_trecords[id % s_shards];
  if (!shard.env) {
    shard.env = getMDBEnv((getArg("filename") + "-" + std::to_string(id % s_shards)).c_str(),
                          MDB_NOSUBDIR | d_asyncFlag, 0600, d_mapsize);
    shard.dbi = shard.env->openDB("records_v5", MDB_CREATE);
  }
  auto ret = std::make_shared<RecordsRWTransaction>(shard.env->getRWTransaction());
  ret->db = std::make_shared<RecordsDB>(shard);

  return ret;
}

std::shared_ptr<LMDBBackend::RecordsROTransaction> LMDBBackend::getRecordsROTransaction(uint32_t id, const std::shared_ptr<LMDBBackend::RecordsRWTransaction>& rwtxn)
{
  auto& shard = d_trecords[id % s_shards];
  if (!shard.env) {
    if (rwtxn) {
      throw DBException("attempting to start nested transaction without open parent env");
    }
    shard.env = getMDBEnv((getArg("filename") + "-" + std::to_string(id % s_shards)).c_str(),
                          MDB_NOSUBDIR | d_asyncFlag, 0600, d_mapsize);
    shard.dbi = shard.env->openDB("records_v5", MDB_CREATE);
  }

  if (rwtxn) {
    auto ret = std::make_shared<RecordsROTransaction>(rwtxn->txn->getROTransaction());
    ret->db = std::make_shared<RecordsDB>(shard);
    return ret;
  }
  else {
    auto ret = std::make_shared<RecordsROTransaction>(shard.env->getROTransaction());
    ret->db = std::make_shared<RecordsDB>(shard);
    return ret;
  }
}

#if 0
// FIXME reinstate soon
bool LMDBBackend::upgradeToSchemav3()
{
  g_log << Logger::Warning << "Upgrading LMDB schema" << endl;

  for (auto i = 0; i < s_shards; i++) {
    string filename = getArg("filename") + "-" + std::to_string(i);
    if (rename(filename.c_str(), (filename + "-old").c_str()) < 0) {
      if (errno == ENOENT) {
        // apparently this shard doesn't exist yet, moving on
        continue;
      }
      unixDie("Rename failed during LMDB upgrade");
    }

    LMDBBackend::RecordsDB oldShard, newShard;

    oldShard.env = getMDBEnv((filename + "-old").c_str(),
                             MDB_NOSUBDIR | d_asyncFlag, 0600);
    oldShard.dbi = oldShard.env->openDB("records", MDB_CREATE | MDB_DUPSORT);
    auto txn = oldShard.env->getROTransaction();
    auto cursor = txn->getROCursor(oldShard.dbi);

    newShard.env = getMDBEnv((filename).c_str(),
                             MDB_NOSUBDIR | d_asyncFlag, 0600);
    newShard.dbi = newShard.env->openDB("records", MDB_CREATE);
    auto newTxn = newShard.env->getRWTransaction();

    MDBOutVal key, val;
    if (cursor.first(key, val) != 0) {
      cursor.close();
      txn->abort();
      newTxn->abort();
      continue;
    }
    string_view currentKey;
    string value;
    for (;;) {
      auto newKey = key.getNoStripHeader<string_view>();
      if (currentKey.compare(newKey) != 0) {
        if (value.size() > 0) {
          newTxn->put(newShard.dbi, currentKey, value);
        }
        currentKey = newKey;
        value = "";
      }
      value += val.get<string>();
      if (cursor.next(key, val) != 0) {
        if (value.size() > 0) {
          newTxn->put(newShard.dbi, currentKey, value);
        }
        break;
      }
    }

    cursor.close();
    txn->commit();
    newTxn->commit();
  }

  return true;
}
#endif

bool LMDBBackend::deleteDomain(const DNSName& domain)
{
  if (!d_rwtxn) {
    throw DBException(std::string(__PRETTY_FUNCTION__) + " called without a transaction");
  }

  int transactionDomainId = d_transactiondomainid;
  DNSName transactionDomain = d_transactiondomain;

  abortTransaction();

  LMDBIDvec idvec;

  if (!d_handle_dups) {
    // get domain id
    DomainInfo info;
    if (findDomain(domain, info)) {
      idvec.push_back(info.id);
    }
  }
  else {
    // this transaction used to be RO.
    // it is now RW to narrow a race window between PowerDNS and Lightning Stream
    // FIXME: turn the entire delete, including this ID scan, into one RW transaction
    // when doing that, first do a short RO check to see if we actually have anything to delete
    auto txn = d_tdomains->getRWTransaction();

    txn.get_multi<0>(domain, idvec);
  }

  for (auto id : idvec) {

    startTransaction(domain, id);

    { // Remove metadata
      auto txn = d_tmeta->getRWTransaction();
      LMDBIDvec ids;

      txn.get_multi<0>(domain, ids);

      for (auto& _id : ids) {
        txn.del(_id);
      }

      txn.commit();
    }

    { // Remove cryptokeys
      auto txn = d_tkdb->getRWTransaction();
      LMDBIDvec ids;
      txn.get_multi<0>(domain, ids);

      for (auto _id : ids) {
        txn.del(_id);
      }

      txn.commit();
    }

    // Remove records
    commitTransaction();

    // Remove zone
    {
      auto container = s_transient_domain_info.write_lock();
      container->remove(static_cast<uint32_t>(id));
    }
    auto txn = d_tdomains->getRWTransaction();
    txn.del(id);
    txn.commit();
  }

  startTransaction(transactionDomain, transactionDomainId);

  return true;
}

bool LMDBBackend::list(const DNSName& target, int /* id */, bool include_disabled)
{
  d_includedisabled = include_disabled;

  DomainInfo info;
  if (!findDomain(target, info)) {
    // cerr << "Did not find " << target << endl;
    return false;
  }
  // cerr << "Found domain " << target << " on domain_id " << info.id << ", list requested " << id << endl;

  d_rotxn = getRecordsROTransaction(info.id, d_rwtxn);
  d_getcursor = std::make_shared<MDBROCursor>(d_rotxn->txn->getCursor(d_rotxn->db->dbi));

  compoundOrdername co;
  d_matchkey = co(info.id);

  MDBOutVal key, val;
  if (d_getcursor->prefix(d_matchkey, key, val) != 0) {
    d_getcursor.reset();
  }

  d_lookupdomain = target;

  // Make sure we start with fresh data
  d_currentrrset.clear();
  d_currentrrsetpos = 0;

  return true;
}

void LMDBBackend::lookup(const QType& type, const DNSName& qdomain, int zoneId, DNSPacket* /* p */)
{
  if (d_dolog) {
    g_log << Logger::Warning << "Got lookup for " << qdomain << "|" << type.toString() << " in zone " << zoneId << endl;
    d_dtime.set();
  }

  d_includedisabled = false;

  DNSName hunt(qdomain);
  DomainInfo info;
  if (zoneId < 0) {
    do {
      if (findDomain(hunt, info)) {
        break;
      }
    } while (type != QType::SOA && hunt.chopOff());
    if (info.id <= 0) {
      //      cout << "Did not find zone for "<< qdomain<<endl;
      d_getcursor.reset();
      return;
    }
  }
  else {
    if (!findDomain(zoneId, info)) {
      // cout<<"Could not find a zone with id "<<zoneId<<endl;
      d_getcursor.reset();
      return;
    }
    hunt = info.zone;
  }

  DNSName relqname = qdomain.makeRelative(hunt);
  if (relqname.empty()) {
    return;
  }
  // cout<<"get will look for "<<relqname<< " in zone "<<hunt<<" with id "<<zoneId<<" and type "<<type.toString()<<endl;
  d_rotxn = getRecordsROTransaction(info.id, d_rwtxn);

  compoundOrdername co;
  d_getcursor = std::make_shared<MDBROCursor>(d_rotxn->txn->getCursor(d_rotxn->db->dbi));
  MDBOutVal key, val;
  if (type.getCode() == QType::ANY) {
    d_matchkey = co(info.id, relqname);
  }
  else {
    d_matchkey = co(info.id, relqname, type.getCode());
  }

  if (d_getcursor->prefix(d_matchkey, key, val) != 0) {
    d_getcursor.reset();
    if (d_dolog) {
      g_log << Logger::Warning << "Query " << ((long)(void*)this) << ": " << d_dtime.udiffNoReset() << " us to execute (found nothing)" << endl;
    }
    return;
  }

  if (d_dolog) {
    g_log << Logger::Warning << "Query " << ((long)(void*)this) << ": " << d_dtime.udiffNoReset() << " us to execute" << endl;
  }

  d_lookupdomain = hunt;

  // Make sure we start with fresh data
  d_currentrrset.clear();
  d_currentrrsetpos = 0;
}

bool LMDBBackend::get(DNSZoneRecord& zr)
{
  for (;;) {
    // std::cerr<<"d_getcursor="<<d_getcursor<<std::endl;
    if (!d_getcursor) {
      d_rotxn.reset();
      return false;
    }

    string_view key;

    if (d_currentrrset.empty()) {
      d_getcursor->current(d_currentKey, d_currentVal);

      key = d_currentKey.getNoStripHeader<string_view>();
      zr.dr.d_type = compoundOrdername::getQType(key).getCode();

      if (zr.dr.d_type == QType::NSEC3) {
        // Hit a magic NSEC3 skipping
        if (d_getcursor->next(d_currentKey, d_currentVal) != 0) {
          // cerr<<"resetting d_getcursor 1"<<endl;
          d_getcursor.reset();
        }
        continue;
      }

      serFromString(d_currentVal.get<string_view>(), d_currentrrset);
      d_currentrrsettime = static_cast<time_t>(LMDBLS::LSgetTimestamp(d_currentVal.getNoStripHeader<string_view>()) / (1000UL * 1000UL * 1000UL));
      d_currentrrsetpos = 0;
    }
    else {
      key = d_currentKey.getNoStripHeader<string_view>();
    }
    try {
      const auto& lrr = d_currentrrset.at(d_currentrrsetpos++);

      zr.disabled = lrr.disabled;
      if (!zr.disabled || d_includedisabled) {
        zr.dr.d_name = compoundOrdername::getQName(key) + d_lookupdomain;
        zr.domain_id = compoundOrdername::getDomainID(key);
        zr.dr.d_type = compoundOrdername::getQType(key).getCode();
        zr.dr.d_ttl = lrr.ttl;
        zr.dr.setContent(deserializeContentZR(zr.dr.d_type, zr.dr.d_name, lrr.content));
        zr.auth = lrr.auth;
      }

      if (d_currentrrsetpos >= d_currentrrset.size()) {
        d_currentrrset.clear(); // will invalidate lrr
        if (d_getcursor->next(d_currentKey, d_currentVal) != 0) {
          // cerr<<"resetting d_getcursor 2"<<endl;
          d_getcursor.reset();
        }
      }

      if (zr.disabled && !d_includedisabled) {
        continue;
      }
    }
    catch (const std::exception& e) {
      throw PDNSException(e.what());
    }

    break;
  }

  return true;
}

bool LMDBBackend::get(DNSResourceRecord& rr)
{
  DNSZoneRecord zr;
  if (!get(zr)) {
    return false;
  }

  rr.qname = zr.dr.d_name;
  rr.ttl = zr.dr.d_ttl;
  rr.qtype = zr.dr.d_type;
  rr.content = zr.dr.getContent()->getZoneRepresentation(true);
  rr.domain_id = zr.domain_id;
  rr.auth = zr.auth;
  rr.disabled = zr.disabled;
  rr.last_modified = d_currentrrsettime;

  return true;
}

bool LMDBBackend::getSerial(DomainInfo& di)
{
  auto txn = getRecordsROTransaction(di.id);
  compoundOrdername co;
  MDBOutVal val;
  if (!txn->txn->get(txn->db->dbi, co(di.id, g_rootdnsname, QType::SOA), val)) {
    LMDBResourceRecord lrr;
    serFromString(val.get<string_view>(), lrr);
    if (lrr.content.size() >= 5 * sizeof(uint32_t)) {
      uint32_t serial;
      // a SOA has five 32 bit fields, the first of which is the serial
      // there are two variable length names before the serial, so we calculate from the back
      memcpy(&serial, &lrr.content[lrr.content.size() - (5 * sizeof(uint32_t))], sizeof(serial));
      di.serial = ntohl(serial);
    }
    return !lrr.disabled;
  }
  return false;
}

bool LMDBBackend::getDomainInfo(const DNSName& domain, DomainInfo& di, bool getserial)
{
  if (!findDomain(domain, di)) {
    return false;
  }
  di.backend = this;
  consolidateDomainInfo(di);

  if (getserial) {
    getSerial(di);
  }

  return true;
}

int LMDBBackend::genChangeDomain(const DNSName& domain, const std::function<void(DomainInfo&)>& func)
{
  DomainInfo info;
  if (!findDomain(domain, info)) {
    return static_cast<int>(false);
  }
  consolidateDomainInfo(info);
  func(info);
  writeDomainInfo(info);
  return true;
}

int LMDBBackend::genChangeDomain(uint32_t id, const std::function<void(DomainInfo&)>& func)
{
  DomainInfo info;
  if (!findDomain(id, info)) {
    return static_cast<int>(false);
  }
  consolidateDomainInfo(info);
  func(info);
  writeDomainInfo(info);
  return true;
}

bool LMDBBackend::setKind(const DNSName& domain, const DomainInfo::DomainKind kind)
{
  return genChangeDomain(domain, [kind](DomainInfo& di) {
    di.kind = kind;
  });
}

bool LMDBBackend::setAccount(const DNSName& domain, const std::string& account)
{
  return genChangeDomain(domain, [account](DomainInfo& di) {
    di.account = account;
  });
}

bool LMDBBackend::setPrimaries(const DNSName& domain, const vector<ComboAddress>& primaries)
{
  return genChangeDomain(domain, [&primaries](DomainInfo& di) {
    di.primaries = primaries;
  });
}

bool LMDBBackend::createDomain(const DNSName& domain, const DomainInfo::DomainKind kind, const vector<ComboAddress>& primaries, const string& account)
{
  DomainInfo info;

  if (findDomain(domain, info)) {
    throw DBException("Domain '" + domain.toLogString() + "' exists already");
  }
  {
    auto txn = d_tdomains->getRWTransaction();

    info.zone = domain;
    info.kind = kind;
    info.primaries = primaries;
    info.account = account;

    txn.put(info, 0, d_random_ids);
    txn.commit();
  }

  return true;
}

void LMDBBackend::getAllDomainsFiltered(vector<DomainInfo>* domains, const std::function<bool(DomainInfo&)>& allow)
{
  auto txn = d_tdomains->getROTransaction();
  if (d_handle_dups) {
    map<DNSName, DomainInfo> zonemap;
    set<DNSName> dups;

    for (auto iter = txn.begin(); iter != txn.end(); ++iter) {
      DomainInfo di = *iter;
      di.id = iter.getID();
      di.backend = this;

      if (!zonemap.emplace(di.zone, di).second) {
        dups.insert(di.zone);
      }
    }

    for (const auto& zone : dups) {
      DomainInfo info;
      // this get grabs the oldest item if there are duplicates
      if (!findDomain(zone, info)) {
        continue;
      }
      info.backend = this;
      zonemap[info.zone] = info;
    }

    for (auto& [k, v] : zonemap) {
      if (allow(v)) {
        consolidateDomainInfo(v);
        domains->push_back(std::move(v));
      }
    }
  }
  else {
    for (auto iter = txn.begin(); iter != txn.end(); ++iter) {
      DomainInfo di = *iter;
      di.id = iter.getID();
      di.backend = this;

      if (allow(di)) {
        consolidateDomainInfo(di);
        domains->push_back(di);
      }
    }
  }
}

void LMDBBackend::getAllDomains(vector<DomainInfo>* domains, bool /* doSerial */, bool include_disabled)
{
  domains->clear();

  getAllDomainsFiltered(domains, [this, include_disabled](DomainInfo& di) {
    if (!getSerial(di) && !include_disabled) {
      return false;
    }

    return true;
  });
}

void LMDBBackend::getUnfreshSecondaryInfos(vector<DomainInfo>* domains)
{
  uint32_t serial;
  time_t now = time(0);
  LMDBResourceRecord lrr;
  soatimes st;

  getAllDomainsFiltered(domains, [this, &lrr, &st, &now, &serial](DomainInfo& di) {
    if (!di.isSecondaryType()) {
      return false;
    }

    auto txn2 = getRecordsROTransaction(di.id);
    compoundOrdername co;
    MDBOutVal val;
    if (!txn2->txn->get(txn2->db->dbi, co(di.id, g_rootdnsname, QType::SOA), val)) {
      serFromString(val.get<string_view>(), lrr);
      memcpy(&st, &lrr.content[lrr.content.size() - sizeof(soatimes)], sizeof(soatimes));
      if ((time_t)(di.last_check + ntohl(st.refresh)) > now) { // still fresh
        return false;
      }
      serial = ntohl(st.serial);
    }
    else {
      serial = 0;
    }

    return true;
  });
}

void LMDBBackend::setStale(uint32_t domain_id)
{
  setLastCheckTime(domain_id, 0);
}

void LMDBBackend::setFresh(uint32_t domain_id)
{
  setLastCheckTime(domain_id, time(nullptr));
}

void LMDBBackend::setLastCheckTime(uint32_t domain_id, time_t last_check)
{
  if (d_write_notification_update) {
    genChangeDomain(domain_id, [last_check](DomainInfo& info) {
      info.last_check = last_check;
    });
    return;
  }

  DomainInfo info;
  if (findDomain(domain_id, info)) {
    auto container = s_transient_domain_info.write_lock();
    TransientDomainInfo tdi;
    container->get(info.id, tdi);
    tdi.last_check = last_check;
    container->update(info.id, tdi);
  }
}

void LMDBBackend::getUpdatedPrimaries(vector<DomainInfo>& updatedDomains, std::unordered_set<DNSName>& catalogs, CatalogHashMap& catalogHashes)
{
  CatalogInfo ci;

  getAllDomainsFiltered(&(updatedDomains), [this, &catalogs, &catalogHashes, &ci](DomainInfo& di) {
    if (!di.isPrimaryType()) {
      return false;
    }

    if (di.kind == DomainInfo::Producer) {
      catalogs.insert(di.zone);
      catalogHashes[di.zone].process("\0");
      return false; // Producer fresness check is performed elsewhere
    }

    if (!di.catalog.empty()) {
      ci.fromJson(di.options, CatalogInfo::CatalogType::Producer);
      ci.updateHash(catalogHashes, di);
    }

    if (getSerial(di) && di.serial != di.notified_serial) {
      di.backend = this;
      return true;
    }

    return false;
  });
}

void LMDBBackend::setNotified(uint32_t domain_id, uint32_t serial)
{
  if (d_write_notification_update) {
    genChangeDomain(domain_id, [serial](DomainInfo& info) {
      info.notified_serial = serial;
    });
    return;
  }

  DomainInfo info;
  if (findDomain(domain_id, info)) {
    auto container = s_transient_domain_info.write_lock();
    TransientDomainInfo tdi;
    container->get(info.id, tdi);
    tdi.notified_serial = serial;
    container->update(info.id, tdi);
  }
}

class getCatalogMembersReturnFalseException : std::runtime_error
{
public:
  getCatalogMembersReturnFalseException() :
    std::runtime_error("getCatalogMembers should return false") {}
};

bool LMDBBackend::getCatalogMembers(const DNSName& catalog, vector<CatalogInfo>& members, CatalogInfo::CatalogType type)
{
  vector<DomainInfo> scratch;

  try {
    getAllDomainsFiltered(&scratch, [&catalog, &members, &type](DomainInfo& di) {
      if ((type == CatalogInfo::CatalogType::Producer && di.kind != DomainInfo::Primary) || (type == CatalogInfo::CatalogType::Consumer && di.kind != DomainInfo::Secondary) || di.catalog != catalog) {
        return false;
      }

      CatalogInfo ci;
      ci.d_id = di.id;
      ci.d_zone = di.zone;
      ci.d_primaries = di.primaries;
      try {
        ci.fromJson(di.options, type);
      }
      catch (const std::runtime_error& e) {
        g_log << Logger::Warning << __PRETTY_FUNCTION__ << " options '" << di.options << "' for zone '" << di.zone << "' is no valid JSON: " << e.what() << endl;
        members.clear();
        throw getCatalogMembersReturnFalseException();
      }
      members.emplace_back(ci);

      return false;
    });
  }
  catch (const getCatalogMembersReturnFalseException& e) {
    return false;
  }
  return true;
}

bool LMDBBackend::setOptions(const DNSName& domain, const std::string& options)
{
  return genChangeDomain(domain, [options](DomainInfo& di) {
    di.options = options;
  });
}

bool LMDBBackend::setCatalog(const DNSName& domain, const DNSName& catalog)
{
  return genChangeDomain(domain, [catalog](DomainInfo& di) {
    di.catalog = catalog;
  });
}

bool LMDBBackend::getAllDomainMetadata(const DNSName& name, std::map<std::string, std::vector<std::string>>& meta)
{
  meta.clear();
  auto txn = d_tmeta->getROTransaction();
  LMDBIDvec ids;
  txn.get_multi<0>(name, ids);

  DomainMeta dm;
  // cerr<<"getAllDomainMetadata start"<<endl;
  for (auto id : ids) {
    if (txn.get(id, dm)) {
      meta[dm.key].push_back(dm.value);
    }
  }
  return true;
}

bool LMDBBackend::setDomainMetadata(const DNSName& name, const std::string& kind, const std::vector<std::string>& meta)
{
  auto txn = d_tmeta->getRWTransaction();

  LMDBIDvec ids;
  txn.get_multi<0>(name, ids);

  DomainMeta dmeta;
  for (auto id : ids) {
    if (txn.get(id, dmeta)) {
      if (dmeta.key == kind) {
        // cerr<<"delete"<<endl;
        txn.del(id);
      }
    }
  }

  for (const auto& m : meta) {
    DomainMeta dm{name, kind, m};
    txn.put(dm, 0, d_random_ids);
  }
  txn.commit();
  return true;
}

bool LMDBBackend::getDomainKeys(const DNSName& name, std::vector<KeyData>& keys)
{
  auto txn = d_tkdb->getROTransaction();
  LMDBIDvec ids;
  txn.get_multi<0>(name, ids);

  KeyDataDB key;

  for (auto id : ids) {
    if (txn.get(id, key)) {
      KeyData kd{key.content, id, key.flags, key.active, key.published};
      keys.push_back(kd);
    }
  }

  return true;
}

bool LMDBBackend::removeDomainKey(const DNSName& name, unsigned int id)
{
  auto txn = d_tkdb->getRWTransaction();
  KeyDataDB kdb;
  if (txn.get(id, kdb)) {
    if (kdb.domain == name) {
      txn.del(id);
      txn.commit();
      return true;
    }
  }
  // cout << "??? wanted to remove domain key for domain "<<name<<" with id "<<id<<", could not find it"<<endl;
  return true;
}

bool LMDBBackend::addDomainKey(const DNSName& name, const KeyData& key, int64_t& id)
{
  auto txn = d_tkdb->getRWTransaction();
  KeyDataDB kdb{name, key.content, key.flags, key.active, key.published};
  id = txn.put(kdb, 0, d_random_ids);
  txn.commit();

  return true;
}

bool LMDBBackend::activateDomainKey(const DNSName& name, unsigned int id)
{
  auto txn = d_tkdb->getRWTransaction();
  KeyDataDB kdb;
  if (txn.get(id, kdb)) {
    if (kdb.domain == name) {
      txn.modify(id, [](KeyDataDB& kdbarg) {
        kdbarg.active = true;
      });
      txn.commit();
      return true;
    }
  }

  // cout << "??? wanted to activate domain key for domain "<<name<<" with id "<<id<<", could not find it"<<endl;
  return true;
}

bool LMDBBackend::deactivateDomainKey(const DNSName& name, unsigned int id)
{
  auto txn = d_tkdb->getRWTransaction();
  KeyDataDB kdb;
  if (txn.get(id, kdb)) {
    if (kdb.domain == name) {
      txn.modify(id, [](KeyDataDB& kdbarg) {
        kdbarg.active = false;
      });
      txn.commit();
      return true;
    }
  }
  // cout << "??? wanted to deactivate domain key for domain "<<name<<" with id "<<id<<", could not find it"<<endl;
  return true;
}

bool LMDBBackend::publishDomainKey(const DNSName& name, unsigned int id)
{
  auto txn = d_tkdb->getRWTransaction();
  KeyDataDB kdb;
  if (txn.get(id, kdb)) {
    if (kdb.domain == name) {
      txn.modify(id, [](KeyDataDB& kdbarg) {
        kdbarg.published = true;
      });
      txn.commit();
      return true;
    }
  }

  // cout << "??? wanted to hide domain key for domain "<<name<<" with id "<<id<<", could not find it"<<endl;
  return true;
}

bool LMDBBackend::unpublishDomainKey(const DNSName& name, unsigned int id)
{
  auto txn = d_tkdb->getRWTransaction();
  KeyDataDB kdb;
  if (txn.get(id, kdb)) {
    if (kdb.domain == name) {
      txn.modify(id, [](KeyDataDB& kdbarg) {
        kdbarg.published = false;
      });
      txn.commit();
      return true;
    }
  }
  // cout << "??? wanted to unhide domain key for domain "<<name<<" with id "<<id<<", could not find it"<<endl;
  return true;
}

// NOLINTNEXTLINE(readability-function-cognitive-complexity)
bool LMDBBackend::getBeforeAndAfterNamesAbsolute(uint32_t id, const DNSName& qname, DNSName& unhashed, DNSName& before, DNSName& after)
{
  //  cout << __PRETTY_FUNCTION__<< ": "<<id <<", "<<qname << " " << unhashed<<endl;

  DomainInfo info;
  if (!findDomain(id, info)) {
    // domain does not exist, tough luck
    return false;
  }
  // cout <<"Zone: "<<info.zone<<endl;

  compoundOrdername co;
  auto txn = getRecordsROTransaction(id);

  auto cursor = txn->txn->getCursor(txn->db->dbi);
  MDBOutVal key, val;

  LMDBResourceRecord lrr;

  string matchkey = co(id, qname, QType::NSEC3);
  if (cursor.lower_bound(matchkey, key, val)) {
    // this is beyond the end of the database
    // cout << "Beyond end of database!" << endl;
    cursor.last(key, val);

    for (;;) {
      if (co.getDomainID(key.getNoStripHeader<StringView>()) != id) {
        //cout<<"Last record also not part of this zone!"<<endl;
        // this implies something is wrong in the database, nothing we can do
        return false;
      }

      if (co.getQType(key.getNoStripHeader<StringView>()) == QType::NSEC3) {
        serFromString(val.get<StringView>(), lrr);
        if (!lrr.ttl) // the kind of NSEC3 we need
          break;
      }
      if (cursor.prev(key, val)) {
        // hit beginning of database, again means something is wrong with it
        return false;
      }
    }
    before = co.getQName(key.getNoStripHeader<StringView>());
    unhashed = DNSName(lrr.content.c_str(), lrr.content.size(), 0, false) + info.zone;

    // now to find after .. at the beginning of the zone
    if (cursor.lower_bound(co(id), key, val)) {
      // cout<<"hit end of zone find when we shouldn't"<<endl;
      return false;
    }
    for (;;) {
      if (co.getQType(key.getNoStripHeader<StringView>()) == QType::NSEC3) {
        serFromString(val.get<StringView>(), lrr);
        if (!lrr.ttl)
          break;
      }

      if (cursor.next(key, val) || co.getDomainID(key.getNoStripHeader<StringView>()) != id) {
        // cout<<"hit end of zone or database when we shouldn't"<<endl;
        return false;
      }
    }
    after = co.getQName(key.getNoStripHeader<StringView>());
    // cout<<"returning: before="<<before<<", after="<<after<<", unhashed: "<<unhashed<<endl;
    return true;
  }

  // cout<<"Ended up at "<<co.getQName(key.get<StringView>()) <<endl;

  before = co.getQName(key.getNoStripHeader<StringView>());
  if (before == qname) {
    // cout << "Ended up on exact right node" << endl;
    before = co.getQName(key.getNoStripHeader<StringView>());
    // unhashed should be correct now, maybe check?
    if (cursor.next(key, val)) {
      // xxx should find first hash now

      if (cursor.lower_bound(co(id), key, val)) {
        // cout<<"hit end of zone find when we shouldn't for id "<<id<< __LINE__<<endl;
        return false;
      }
      for (;;) {
        if (co.getQType(key.getNoStripHeader<StringView>()) == QType::NSEC3) {
          serFromString(val.get<StringView>(), lrr);
          if (!lrr.ttl)
            break;
        }

        if (cursor.next(key, val) || co.getDomainID(key.getNoStripHeader<StringView>()) != id) {
          // cout<<"hit end of zone or database when we shouldn't" << __LINE__<<endl;
          return false;
        }
      }
      after = co.getQName(key.getNoStripHeader<StringView>());
      // cout<<"returning: before="<<before<<", after="<<after<<", unhashed: "<<unhashed<<endl;
      return true;
    }
  }
  else {
    // cout <<"Going backwards to find 'before'"<<endl;
    int count = 0;
    for (;;) {
      if (co.getQName(key.getNoStripHeader<StringView>()).canonCompare(qname) && co.getQType(key.getNoStripHeader<StringView>()) == QType::NSEC3) {
        // cout<<"Potentially stopping traverse at "<< co.getQName(key.get<StringView>()) <<", " << (co.getQName(key.get<StringView>()).canonCompare(qname))<<endl;
        // cout<<"qname = "<<qname<<endl;
        // cout<<"here  = "<<co.getQName(key.get<StringView>())<<endl;
        serFromString(val.get<StringView>(), lrr);
        if (!lrr.ttl)
          break;
      }

      if (cursor.prev(key, val) || co.getDomainID(key.getNoStripHeader<StringView>()) != id) {
        // cout <<"XXX Hit *beginning* of zone or database"<<endl;
        // this can happen, must deal with it
        // should now find the last hash of the zone

        if (cursor.lower_bound(co(id + 1), key, val)) {
          // cout << "Could not find the next higher zone, going to the end of the database then"<<endl;
          cursor.last(key, val);
        }
        else
          cursor.prev(key, val);

        for (;;) {
          if (co.getDomainID(key.getNoStripHeader<StringView>()) != id) {
            //cout<<"Last record also not part of this zone!"<<endl;
            // this implies something is wrong in the database, nothing we can do
            return false;
          }

          if (co.getQType(key.getNoStripHeader<StringView>()) == QType::NSEC3) {
            serFromString(val.get<StringView>(), lrr);
            if (!lrr.ttl) // the kind of NSEC3 we need
              break;
          }
          if (cursor.prev(key, val)) {
            // hit beginning of database, again means something is wrong with it
            return false;
          }
        }
        before = co.getQName(key.getNoStripHeader<StringView>());
        unhashed = DNSName(lrr.content.c_str(), lrr.content.size(), 0, false) + info.zone;
        // cout <<"Should still find 'after'!"<<endl;
        // for 'after', we need to find the first hash of this zone

        if (cursor.lower_bound(co(id), key, val)) {
          // cout<<"hit end of zone find when we shouldn't"<<endl;
          // means database is wrong, nothing we can do
          return false;
        }
        for (;;) {
          if (co.getQType(key.getNoStripHeader<StringView>()) == QType::NSEC3) {
            serFromString(val.get<StringView>(), lrr);
            if (!lrr.ttl)
              break;
          }

          if (cursor.next(key, val)) {
            // means database is wrong, nothing we can do
            // cout<<"hit end of zone when we shouldn't 2"<<endl;
            return false;
          }
        }
        after = co.getQName(key.getNoStripHeader<StringView>());

        // cout<<"returning: before="<<before<<", after="<<after<<", unhashed: "<<unhashed<<endl;
        return true;
      }
      ++count;
    }
    before = co.getQName(key.getNoStripHeader<StringView>());
    unhashed = DNSName(lrr.content.c_str(), lrr.content.size(), 0, false) + info.zone;
    // cout<<"Went backwards, found "<<before<<endl;
    // return us to starting point
    while (count--)
      cursor.next(key, val);
  }
  //  cout<<"Now going forward"<<endl;
  for (int count = 0;; ++count) {
    if ((count && cursor.next(key, val)) || co.getDomainID(key.getNoStripHeader<StringView>()) != id) {
      // cout <<"Hit end of database or zone, finding first hash then in zone "<<id<<endl;
      if (cursor.lower_bound(co(id), key, val)) {
        // cout<<"hit end of zone find when we shouldn't"<<endl;
        // means database is wrong, nothing we can do
        return false;
      }
      for (;;) {
        if (co.getQType(key.getNoStripHeader<StringView>()) == QType::NSEC3) {
          serFromString(val.get<StringView>(), lrr);
          if (!lrr.ttl)
            break;
        }

        if (cursor.next(key, val)) {
          // means database is wrong, nothing we can do
          // cout<<"hit end of zone when we shouldn't 2"<<endl;
          return false;
        }
        // cout << "Next.. "<<endl;
      }
      after = co.getQName(key.getNoStripHeader<StringView>());

      // cout<<"returning: before="<<before<<", after="<<after<<", unhashed: "<<unhashed<<endl;
      return true;
    }

    // cout<<"After "<<co.getQName(key.get<StringView>()) <<endl;
    if (co.getQType(key.getNoStripHeader<StringView>()) == QType::NSEC3) {
      serFromString(val.get<StringView>(), lrr);
      if (!lrr.ttl) {
        break;
      }
    }
  }
  after = co.getQName(key.getNoStripHeader<StringView>());
  // cout<<"returning: before="<<before<<", after="<<after<<", unhashed: "<<unhashed<<endl;
  return true;
}

bool LMDBBackend::getBeforeAndAfterNames(uint32_t id, const DNSName& zonenameU, const DNSName& qname, DNSName& before, DNSName& after)
{
  DNSName zonename = zonenameU.makeLowerCase();
  //  cout << __PRETTY_FUNCTION__<< ": "<<id <<", "<<zonename << ", '"<<qname<<"'"<<endl;

  auto txn = getRecordsROTransaction(id);
  compoundOrdername co;
  DNSName qname2 = qname.makeRelative(zonename);
  string matchkey = co(id, qname2);
  auto cursor = txn->txn->getCursor(txn->db->dbi);
  MDBOutVal key, val;
  // cout<<"Lower_bound for "<<qname2<<endl;
  if (cursor.lower_bound(matchkey, key, val)) {
    // cout << "Hit end of database, bummer"<<endl;
    cursor.last(key, val);
    if (co.getDomainID(key.getNoStripHeader<string_view>()) == id) {
      before = co.getQName(key.getNoStripHeader<string_view>()) + zonename;
      after = zonename;
    }
    // else
    // cout << "We were at end of database, but this zone is not there?!"<<endl;
    return true;
  }
  // cout<<"Cursor is at "<<co.getQName(key.get<string_view>()) <<", in zone id "<<co.getDomainID(key.get<string_view>())<< endl;

  if (co.getQType(key.getNoStripHeader<string_view>()).getCode() && co.getDomainID(key.getNoStripHeader<string_view>()) == id && co.getQName(key.getNoStripHeader<string_view>()) == qname2) { // don't match ENTs
    // cout << "Had an exact match!"<<endl;
    before = qname2 + zonename;
    int rc;
    for (;;) {
      rc = cursor.next(key, val);
      if (rc)
        break;

      if (co.getDomainID(key.getNoStripHeader<string_view>()) == id && key.getNoStripHeader<StringView>().rfind(matchkey, 0) == 0)
        continue;
      LMDBResourceRecord lrr;
      serFromString(val.get<StringView>(), lrr);
      if (co.getQType(key.getNoStripHeader<string_view>()).getCode() && (lrr.auth || co.getQType(key.getNoStripHeader<string_view>()).getCode() == QType::NS))
        break;
    }
    if (rc || co.getDomainID(key.getNoStripHeader<string_view>()) != id) {
      // cout << "We hit the end of the zone or database. 'after' is apex" << endl;
      after = zonename;
      return false;
    }
    after = co.getQName(key.getNoStripHeader<string_view>()) + zonename;
    return true;
  }

  if (co.getDomainID(key.getNoStripHeader<string_view>()) != id) {
    // cout << "Ended up in next zone, 'after' is zonename" <<endl;
    after = zonename;
    // cout << "Now hunting for previous" << endl;
    int rc;
    for (;;) {
      rc = cursor.prev(key, val);
      if (rc) {
        // cout<<"Reversed into zone, but got not found from lmdb" <<endl;
        return false;
      }

      if (co.getDomainID(key.getNoStripHeader<string_view>()) != id) {
        // cout<<"Reversed into zone, but found wrong zone id " << co.getDomainID(key.getNoStripHeader<string_view>()) << " != "<<id<<endl;
        // "this can't happen"
        return false;
      }
      LMDBResourceRecord lrr;
      serFromString(val.get<StringView>(), lrr);
      if (co.getQType(key.getNoStripHeader<string_view>()).getCode() && (lrr.auth || co.getQType(key.getNoStripHeader<string_view>()).getCode() == QType::NS))
        break;
    }

    before = co.getQName(key.getNoStripHeader<string_view>()) + zonename;
    // cout<<"Found: "<< before<<endl;
    return true;
  }

  // cout <<"We ended up after "<<qname<<", on "<<co.getQName(key.getNoStripHeader<string_view>())<<endl;

  int skips = 0;
  for (;;) {
    LMDBResourceRecord lrr;
    serFromString(val.get<StringView>(), lrr);
    if (co.getQType(key.getNoStripHeader<string_view>()).getCode() && (lrr.auth || co.getQType(key.getNoStripHeader<string_view>()).getCode() == QType::NS)) {
      after = co.getQName(key.getNoStripHeader<string_view>()) + zonename;
      // cout <<"Found auth ("<<lrr.auth<<") or an NS record "<<after<<", type: "<<co.getQType(key.getNoStripHeader<string_view>()).toString()<<", ttl = "<<lrr.ttl<<endl;
      // cout << makeHexDump(val.get<string>()) << endl;
      break;
    }
    // cout <<"  oops, " << co.getQName(key.getNoStripHeader<string_view>()) << " was not auth "<<lrr.auth<< " type=" << lrr.qtype.toString()<<" or NS, so need to skip ahead a bit more" << endl;
    int rc = cursor.next(key, val);
    if (!rc)
      ++skips;
    if (rc || co.getDomainID(key.getNoStripHeader<string_view>()) != id) {
      // cout << "  oops, hit end of database or zone. This means after is apex" <<endl;
      after = zonename;
      break;
    }
  }
  // go back to where we were
  while (skips--)
    cursor.prev(key, val);

  for (;;) {
    int rc = cursor.prev(key, val);
    if (rc || co.getDomainID(key.getNoStripHeader<string_view>()) != id) {
      // XX I don't think this case can happen
      // cout << "We hit the beginning of the zone or database.. now what" << endl;
      return false;
    }
    before = co.getQName(key.getNoStripHeader<string_view>()) + zonename;
    LMDBResourceRecord lrr;
    serFromString(val.get<string_view>(), lrr);
    // cout<<"And before to "<<before<<", auth = "<<rr.auth<<endl;
    if (co.getQType(key.getNoStripHeader<string_view>()).getCode() && (lrr.auth || co.getQType(key.getNoStripHeader<string_view>()) == QType::NS))
      break;
    // cout << "Oops, that was wrong, go back one more"<<endl;
  }

  return true;
}

bool LMDBBackend::updateDNSSECOrderNameAndAuth(uint32_t domain_id, const DNSName& qname, const DNSName& ordername, bool auth, const uint16_t qtype)
{
  //  cout << __PRETTY_FUNCTION__<< ": "<< domain_id <<", '"<<qname <<"', '"<<ordername<<"', "<<auth<< ", " << qtype << endl;
  shared_ptr<RecordsRWTransaction> txn;
  bool needCommit = false;
  if (d_rwtxn && d_transactiondomainid == domain_id) {
    txn = d_rwtxn;
    //    cout<<"Reusing open transaction"<<endl;
  }
  else {
    //    cout<<"Making a new RW txn for " << __PRETTY_FUNCTION__ <<endl;
    txn = getRecordsRWTransaction(domain_id);
    needCommit = true;
  }

  DomainInfo info;
  if (!findDomain(domain_id, info)) {
    //    cout<<"Could not find domain_id "<<domain_id <<endl;
    return false;
  }

  DNSName rel = qname.makeRelative(info.zone);

  compoundOrdername co;
  string matchkey = co(domain_id, rel);

  auto cursor = txn->txn->getCursor(txn->db->dbi);
  MDBOutVal key, val;
  if (cursor.prefix(matchkey, key, val) != 0) {
    // cout << "Could not find anything"<<endl;
    return false;
  }

  bool hasOrderName = !ordername.empty();
  bool needNSEC3 = hasOrderName;

  do {
    vector<LMDBResourceRecord> lrrs;

    if (co.getQType(key.getNoStripHeader<StringView>()) != QType::NSEC3) {
      serFromString(val.get<StringView>(), lrrs);
      bool changed = false;
      vector<LMDBResourceRecord> newRRs;
      for (auto& lrr : lrrs) {
        lrr.qtype = co.getQType(key.getNoStripHeader<StringView>());
        if (!needNSEC3 && qtype != QType::ANY) {
          needNSEC3 = (lrr.ordername && QType(qtype) != lrr.qtype);
        }

        if ((qtype == QType::ANY || QType(qtype) == lrr.qtype) && (lrr.ordername != hasOrderName || lrr.auth != auth)) {
          lrr.auth = auth;
          lrr.ordername = hasOrderName;
          changed = true;
        }
        newRRs.push_back(std::move(lrr));
      }
      if (changed) {
        cursor.put(key, serToString(newRRs));
      }
    }

  } while (cursor.next(key, val) == 0);

  bool del = false;
  LMDBResourceRecord lrr;
  matchkey = co(domain_id, rel, QType::NSEC3);
  // cerr<<"here qname="<<qname<<" ordername="<<ordername<<" qtype="<<qtype<<" matchkey="<<makeHexDump(matchkey)<<endl;
  int txngetrc;
  if (!(txngetrc = txn->txn->get(txn->db->dbi, matchkey, val))) {
    serFromString(val.get<string_view>(), lrr);

    if (needNSEC3) {
      if (hasOrderName && lrr.content != ordername.toDNSStringLC()) {
        del = true;
      }
    }
    else {
      del = true;
    }
    if (del) {
      txn->txn->del(txn->db->dbi, co(domain_id, DNSName(lrr.content.c_str(), lrr.content.size(), 0, false), QType::NSEC3));
      txn->txn->del(txn->db->dbi, matchkey);
    }
  }
  else {
    del = true;
  }

  if (hasOrderName && del) {
    matchkey = co(domain_id, rel, QType::NSEC3);

    lrr.ttl = 0;
    lrr.auth = 0;
    lrr.content = rel.toDNSStringLC();

    string str = serToString(lrr);
    txn->txn->put(txn->db->dbi, co(domain_id, ordername, QType::NSEC3), str);
    lrr.ttl = 1;
    lrr.content = ordername.toDNSStringLC();
    str = serToString(lrr);
    txn->txn->put(txn->db->dbi, matchkey, str); // 2
  }

  if (needCommit)
    txn->txn->commit();
  return false;
}

bool LMDBBackend::updateEmptyNonTerminals(uint32_t domain_id, set<DNSName>& insert, set<DNSName>& erase, bool remove)
{
  // cout << __PRETTY_FUNCTION__<< ": "<< domain_id << ", insert.size() "<<insert.size()<<", "<<erase.size()<<", " <<remove<<endl;

  bool needCommit = false;
  shared_ptr<RecordsRWTransaction> txn;
  if (d_rwtxn && d_transactiondomainid == domain_id) {
    txn = d_rwtxn;
    //    cout<<"Reusing open transaction"<<endl;
  }
  else {
    //    cout<<"Making a new RW txn for delete domain"<<endl;
    txn = getRecordsRWTransaction(domain_id);
    needCommit = true;
  }

  DomainInfo info;
  if (!findDomain(domain_id, info)) {
    // cout <<"No such domain with id "<<domain_id<<endl;
    return false;
  }

  // if remove is set, all ENTs should be removed & nothing else should be done
  if (remove) {
    deleteDomainRecords(*txn, domain_id, 0);
  }
  else {
    compoundOrdername co;
    for (const auto& n : insert) {
      LMDBResourceRecord lrr;
      lrr.qname = n.makeRelative(info.zone);
      lrr.ttl = 0;
      lrr.auth = true;

      std::string ser = serToString(lrr);

      txn->txn->put(txn->db->dbi, co(domain_id, lrr.qname, 0), ser);

      // cout <<" +"<<n<<endl;
    }
    for (auto n : erase) {
      // cout <<" -"<<n<<endl;
      n.makeUsRelative(info.zone);
      txn->txn->del(txn->db->dbi, co(domain_id, n, 0));
    }
  }
  if (needCommit)
    txn->txn->commit();
  return false;
}

/* TSIG */
bool LMDBBackend::getTSIGKey(const DNSName& name, DNSName& algorithm, string& content)
{
  auto txn = d_ttsig->getROTransaction();
  LMDBIDvec ids;
  txn.get_multi<0>(name, ids);

  TSIGKey key;
  for (auto id : ids) {
    if (txn.get(id, key)) {
      if (algorithm.empty() || algorithm == DNSName(key.algorithm)) {
        algorithm = DNSName(key.algorithm);
        content = key.key;
      }
    }
  }

  return true;
}

// this deletes an old key if it has the same algorithm
bool LMDBBackend::setTSIGKey(const DNSName& name, const DNSName& algorithm, const string& content)
{
  auto txn = d_ttsig->getRWTransaction();

  LMDBIDvec ids;
  txn.get_multi<0>(name, ids);

  TSIGKey key;
  for (auto id : ids) {
    if (txn.get(id, key)) {
      if (key.algorithm == algorithm) {
        txn.del(id);
      }
    }
  }

  TSIGKey tk;
  tk.name = name;
  tk.algorithm = algorithm;
  tk.key = content;

  txn.put(tk, 0, d_random_ids);
  txn.commit();

  return true;
}
bool LMDBBackend::deleteTSIGKey(const DNSName& name)
{
  auto txn = d_ttsig->getRWTransaction();

  LMDBIDvec ids;
  txn.get_multi<0>(name, ids);

  TSIGKey key;

  for (auto id : ids) {
    if (txn.get(id, key)) {
      txn.del(id);
    }
  }
  txn.commit();
  return true;
}
bool LMDBBackend::getTSIGKeys(std::vector<struct TSIGKey>& keys)
{
  auto txn = d_ttsig->getROTransaction();

  keys.clear();
  for (auto iter = txn.begin(); iter != txn.end(); ++iter) {
    keys.push_back(*iter);
  }
  return true;
}

string LMDBBackend::directBackendCmd(const string& query)
{
  ostringstream ret, usage;

  usage << "info                               show some information about the database" << endl;
  usage << "index check domains                check zone<>ID indexes" << endl;
  usage << "index refresh domains <ID>         refresh index for zone with this ID" << endl;
  usage << "index refresh-all domains          refresh index for all zones with disconnected indexes" << endl;
  vector<string> argv;
  stringtok(argv, query);

  if (argv.empty()) {
    return usage.str();
  }

  string& cmd = argv[0];

  if (cmd == "help") {
    return usage.str();
  }

  if (cmd == "info") {
    ret << "shards: " << s_shards << endl;
    ret << "schemaversion: " << SCHEMAVERSION << endl;

    return ret.str();
  }

  if (cmd == "index") {
    if (argv.size() < 2) {
      return "need an index subcommand\n";
    }

    string& subcmd = argv[1];

    if (subcmd == "check" || subcmd == "refresh-all") {
      bool refresh = false;

      if (subcmd == "refresh-all") {
        refresh = true;
      }

      if (argv.size() < 3) {
        return "need an index name\n";
      }

      if (argv[2] != "domains") {
        return "can only check the domains index\n";
      }

      vector<uint32_t> refreshQueue;

      {
        auto txn = d_tdomains->getROTransaction();

        for (auto iter = txn.begin(); iter != txn.end(); ++iter) {
          DomainInfo di = *iter;

          auto id = iter.getID();

          LMDBIDvec ids;
          txn.get_multi<0>(di.zone, ids);

          if (ids.size() != 1) {
            ret << "ID->zone index has " << id << "->" << di.zone << ", ";

            if (ids.empty()) {
              ret << "zone->ID index has no entry for " << di.zone << endl;
              if (refresh) {
                refreshQueue.push_back(id);
              }
              else {
                ret << "  suggested remedy: index refresh domains " << id << endl;
              }
            }
            else {
              // ids.size() > 1
              ret << "zone->ID index has multiple entries for " << di.zone << ": ";
              for (auto id_ : ids) {
                ret << id_ << " ";
              }
              ret << endl;
            }
          }
        }
      }

      if (refresh) {
        for (const auto& id : refreshQueue) {
          if (genChangeDomain(id, [](DomainInfo& /* di */) {})) {
            ret << "refreshed " << id << endl;
          }
          else {
            ret << "failed to refresh " << id << endl;
          }
        }
      }
      return ret.str();
    }
    if (subcmd == "refresh") {
      // index refresh domains 12345
      if (argv.size() < 4) {
        return "usage: index refresh domains <ID>\n";
      }

      if (argv[2] != "domains") {
        return "can only refresh in the domains index\n";
      }

      uint32_t id = 0;

      try {
        id = pdns::checked_stoi<uint32_t>(argv[3]);
      }
      catch (const std::out_of_range& e) {
        return "ID out of range\n";
      }

      if (genChangeDomain(id, [](DomainInfo& /* di */) {})) {
        ret << "refreshed" << endl;
      }
      else {
        ret << "failed" << endl;
      }
      return ret.str();
    }
  }

  return "unknown lmdbbackend command\n";
}

class LMDBFactory : public BackendFactory
{
public:
  LMDBFactory() :
    BackendFactory("lmdb") {}
  void declareArguments(const string& suffix = "") override
  {
    declare(suffix, "filename", "Filename for lmdb", "./pdns.lmdb");
    declare(suffix, "sync-mode", "Synchronisation mode: nosync, nometasync, sync", "sync");
    // there just is no room for more on 32 bit
    declare(suffix, "shards", "Records database will be split into this number of shards", (sizeof(void*) == 4) ? "2" : "64");
    declare(suffix, "schema-version", "Maximum allowed schema version to run on this DB. If a lower version is found, auto update is performed", std::to_string(SCHEMAVERSION));
    declare(suffix, "random-ids", "Numeric IDs inside the database are generated randomly instead of sequentially", "no");
    declare(suffix, "map-size", "LMDB map size in megabytes", (sizeof(void*) == 4) ? "100" : "16000");
    declare(suffix, "flag-deleted", "Flag entries on deletion instead of deleting them", "no");
    declare(suffix, "write-notification-update", "Do not update domain table upon notification", "yes");
    declare(suffix, "lightning-stream", "Run in Lightning Stream compatible mode", "no");
  }
  DNSBackend* make(const string& suffix = "") override
  {
    return new LMDBBackend(suffix);
  }
};

/* THIRD PART */

class LMDBLoader
{
public:
  LMDBLoader()
  {
    BackendMakers().report(std::make_unique<LMDBFactory>());
    g_log << Logger::Info << "[lmdbbackend] This is the lmdb backend version " VERSION
#ifndef REPRODUCIBLE
          << " (" __DATE__ " " __TIME__ ")"
#endif
          << " reporting" << endl;
  }
};

static LMDBLoader randomLoader;
