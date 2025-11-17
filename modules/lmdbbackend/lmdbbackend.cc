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

#include "lmdbbackend.hh"

#include "config.h"
#include "ext/lmdb-safe/lmdb-safe.hh"
#include "pdns/arguments.hh"
#include "pdns/base32.hh"
#include "pdns/dns.hh"
#include "pdns/dnsbackend.hh"
#include "pdns/dnsname.hh"
#include "pdns/dnspacket.hh"
#include "pdns/dnssecinfra.hh"
#include "pdns/logger.hh"
#include "pdns/misc.hh"
#include "pdns/pdnsexception.hh"
#include "pdns/uuid-utils.hh"
#include <boost/archive/binary_iarchive.hpp>
#include <boost/archive/binary_oarchive.hpp>
#include <boost/iostreams/device/back_inserter.hpp>
#include <boost/serialization/string.hpp>
#include <boost/serialization/utility.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/uuid/uuid_serialize.hpp>
#include <cstdio>
#include <cstring>
#include <lmdb.h>
#include <memory>
#include <stdexcept>
#include <unistd.h>
#include <utility>

#ifdef HAVE_SYSTEMD
#include <systemd/sd-daemon.h>
#endif

constexpr unsigned int SCHEMAVERSION{6};

// List the class version here. Default is 0
BOOST_CLASS_VERSION(LMDBBackend::KeyDataDB, 1)
BOOST_CLASS_VERSION(ZoneName, 1)
BOOST_CLASS_VERSION(DomainInfo, 2)

static bool s_first = true;
static uint32_t s_shards = 0;
static std::mutex s_lmdbStartupLock;

std::pair<uint32_t, uint32_t> LMDBBackend::getSchemaVersionAndShards(std::string& filename)
{
  // cerr << "getting schema version for path " << filename << endl;

  uint32_t schemaversion = 0;

  MDB_env* tmpEnv = nullptr;

  if (int retCode = mdb_env_create(&tmpEnv); retCode != 0) {
    throw std::runtime_error("mdb_env_create failed: " + MDBError(retCode));
  }

  std::unique_ptr<MDB_env, decltype(&mdb_env_close)> env{tmpEnv, mdb_env_close};

  if (int retCode = mdb_env_set_mapsize(tmpEnv, 0); retCode != 0) {
    throw std::runtime_error("mdb_env_set_mapsize failed: " + MDBError(retCode));
  }

  if (int retCode = mdb_env_set_maxdbs(tmpEnv, 20); retCode != 0) { // we need 17: 1 {"pdns"} + 4 {"domains", "keydata", "tsig", "metadata"} * 2 {v4, v5} * 2 {main, index in _0}
    throw std::runtime_error("mdb_env_set_maxdbs failed: " + MDBError(retCode));
  }

  {
    int retCode = mdb_env_open(tmpEnv, filename.c_str(), MDB_NOSUBDIR | MDB_RDONLY, 0600);
    if (retCode != 0) {
      if (retCode == ENOENT) {
        // we don't have a database yet! report schema 0, with 0 shards
        return {0U, 0U};
      }
      throw std::runtime_error("mdb_env_open failed: " + MDBError(retCode));
    }
  }

  MDB_txn* txn = nullptr;

  if (int retCode = mdb_txn_begin(tmpEnv, nullptr, MDB_RDONLY, &txn); retCode != 0) {
    throw std::runtime_error("mdb_txn_begin failed: " + MDBError(retCode));
  }

  MDB_dbi dbi;

  {
    int retCode = MDBDbi::mdb_dbi_open(txn, "pdns", 0, &dbi);
    if (retCode != 0) {
      if (retCode == MDB_NOTFOUND) {
        // this means nothing has been inited yet
        // we pretend this means the latest schema
        mdb_txn_abort(txn);
        return {SCHEMAVERSION, 0U};
      }
      mdb_txn_abort(txn);
      throw std::runtime_error("mdb_dbi_open failed: " + MDBError(retCode));
    }
  }

  MDB_val key, data;

  key.mv_data = (char*)"schemaversion";
  key.mv_size = strlen((char*)key.mv_data);

  {
    int retCode = mdb_get(txn, dbi, &key, &data);
    if (retCode != 0) {
      if (retCode == MDB_NOTFOUND) {
        // this means nothing has been inited yet
        // we pretend this means the latest schema
        mdb_txn_abort(txn);
        return {SCHEMAVERSION, 0U};
      }

      throw std::runtime_error("mdb_get pdns.schemaversion failed: " + MDBError(retCode));
    }
  }

  if (data.mv_size == 4) {
    // schemaversion is < 5 and is stored in 32 bits, in host order

    memcpy(&schemaversion, data.mv_data, data.mv_size);
  }
  else if (data.mv_size >= LMDBLS::LS_MIN_HEADER_SIZE + sizeof(schemaversion)) {
    // schemaversion is >= 5, stored in 32 bits, network order, after the LS header

    // FIXME: get actual header size (including extension blocks) instead of just reading from the back
    // FIXME: add a test for reading schemaversion and shards (and actual data, later) when there are variably sized headers
    memcpy(&schemaversion, (char*)data.mv_data + data.mv_size - sizeof(schemaversion), sizeof(schemaversion));
    schemaversion = ntohl(schemaversion);
  }
  else {
    throw std::runtime_error("pdns.schemaversion had unexpected size");
  }

  uint32_t shards = 0;

  key.mv_data = (char*)"shards";
  key.mv_size = strlen((char*)key.mv_data);

  {
    int retCode = mdb_get(txn, dbi, &key, &data);
    if (retCode != 0) {
      if (retCode == MDB_NOTFOUND) {
        cerr << "schemaversion was set, but shards was not. Dazed and confused, trying to exit." << endl;
        mdb_txn_abort(txn);
        // NOLINTNEXTLINE(concurrency-mt-unsafe)
        exit(1);
      }

      throw std::runtime_error("mdb_get pdns.shards failed: " + MDBError(retCode));
    }
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
    throw std::runtime_error("mdb_cursor_open failed: " + MDBError(rc));
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
      throw std::runtime_error("mdb_put failed: " + MDBError(rc));
    }

    rc = mdb_cursor_get(cur, &key, &data, MDB_NEXT);
  }
  if (rc != MDB_NOTFOUND) {
    throw std::runtime_error("error while iterating dbi: " + MDBError(rc));
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
    throw std::runtime_error("mdb_cursor_open failed: " + MDBError(rc));
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
      throw std::runtime_error("mdb_put failed: " + MDBError(rc));
    }

    rc = mdb_cursor_get(cur, &key, &data, MDB_NEXT);
  }
  if (rc != MDB_NOTFOUND) {
    throw std::runtime_error("error while iterating dbi: " + MDBError(rc));
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
    throw std::runtime_error("mdb_cursor_open failed: " + MDBError(rc));
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
      throw std::runtime_error("mdb_put failed: " + MDBError(rc));
    }

    rc = mdb_cursor_get(cur, &key, &data, MDB_NEXT);
  }
  if (rc != MDB_NOTFOUND) {
    throw std::runtime_error("error while iterating dbi: " + MDBError(rc));
  }
}

}

bool LMDBBackend::upgradeToSchemav5(std::string& filename, uint32_t currentSchemaVersion, uint32_t shardCount)
{
  if (currentSchemaVersion != 3 && currentSchemaVersion != 4) {
    throw std::runtime_error("upgrade to v5 requested but current schema is not v3 or v4, stopping");
  }

  MDB_env* env = nullptr;

  if (int retCode = mdb_env_create(&env); retCode != 0) {
    throw std::runtime_error("mdb_env_create failed: " + MDBError(retCode));
  }

  if (int retCode = mdb_env_set_maxdbs(env, 20); retCode != 0) {
    mdb_env_close(env);
    throw std::runtime_error("mdb_env_set_maxdbs failed: " + MDBError(retCode));
  }

  if (int retCode = mdb_env_open(env, filename.c_str(), MDB_NOSUBDIR, 0600); retCode != 0) {
    mdb_env_close(env);
    throw std::runtime_error("mdb_env_open failed: " + MDBError(retCode));
  }

  MDB_txn* txn = nullptr;

  if (int retCode = mdb_txn_begin(env, nullptr, 0, &txn); retCode != 0) {
    mdb_env_close(env);
    throw std::runtime_error("mdb_txn_begin failed: " + MDBError(retCode));
  }

#ifdef HAVE_SYSTEMD
  /* A schema migration may take a long time. Extend the startup service timeout to 1 day,
   * but only if this is beyond the original maximum time of TimeoutStartSec=.
   */
  sd_notify(0, "EXTEND_TIMEOUT_USEC=86400000000");
#endif

  std::cerr << "migrating shards" << std::endl;
  for (uint32_t i = 0; i < shardCount; i++) {
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

    if (int retCode = mdb_env_create(&shenv); retCode != 0) {
      throw std::runtime_error("mdb_env_create failed: " + MDBError(retCode));
    }

    if (int retCode = mdb_env_set_maxdbs(shenv, 8); retCode != 0) {
      mdb_env_close(env);
      throw std::runtime_error("mdb_env_set_maxdbs failed: " + MDBError(retCode));
    }

    if (int retCode = mdb_env_open(shenv, shardfile.c_str(), MDB_NOSUBDIR, 0600); retCode != 0) {
      mdb_env_close(env);
      throw std::runtime_error("mdb_env_open failed: " + MDBError(retCode));
    }

    MDB_txn* shtxn = nullptr;

    if (int retCode = mdb_txn_begin(shenv, nullptr, 0, &shtxn); retCode != 0) {
      mdb_env_close(env);
      throw std::runtime_error("mdb_txn_begin failed: " + MDBError(retCode));
    }

    MDB_dbi shdbi = 0;

    const auto dbiOpenRc = MDBDbi::mdb_dbi_open(shtxn, "records", 0, &shdbi);
    if (dbiOpenRc != 0) {
      if (dbiOpenRc == MDB_NOTFOUND) {
        mdb_txn_abort(shtxn);
        mdb_env_close(shenv);
        continue;
      }
      mdb_txn_abort(shtxn);
      mdb_env_close(shenv);
      throw std::runtime_error("mdb_dbi_open shard records failed: " + MDBError(dbiOpenRc));
    }

    MDB_dbi shdbi2 = 0;

    if (int retCode = MDBDbi::mdb_dbi_open(shtxn, "records_v5", MDB_CREATE, &shdbi2); retCode != 0) {
      mdb_dbi_close(shenv, shdbi);
      mdb_txn_abort(shtxn);
      mdb_env_close(shenv);
      throw std::runtime_error("mdb_dbi_open shard records_v5 failed: " + MDBError(retCode));
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

  std::array<MDB_dbi, 4> fromtypeddbi{};
  std::array<MDB_dbi, 4> totypeddbi{};

  int index = 0;

  for (const std::string dbname : {"domains", "keydata", "tsig", "metadata"}) {
    std::cerr << "migrating " << dbname << std::endl;
    std::string tdbname = dbname + "_v5";

    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
    if (int retCode = MDBDbi::mdb_dbi_open(txn, dbname.c_str(), 0, &fromtypeddbi[index]); retCode != 0) {
      mdb_txn_abort(txn);
      mdb_env_close(env);
      throw std::runtime_error("MDBDbi::mdb_dbi_open typeddbi failed: " + MDBError(retCode));
    }

    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
    if (int retCode = MDBDbi::mdb_dbi_open(txn, tdbname.c_str(), MDB_CREATE, &totypeddbi[index]); retCode != 0) {
      // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
      mdb_dbi_close(env, fromtypeddbi[index]);
      mdb_txn_abort(txn);
      mdb_env_close(env);
      throw std::runtime_error("mdb_dbi_open typeddbi target failed: " + MDBError(retCode));
    }

    try {
      // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
      copyTypedDBI(txn, fromtypeddbi[index], totypeddbi[index]);
    }
    catch (std::exception& e) {
      // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
      mdb_dbi_close(env, totypeddbi[index]);
      // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
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

  std::array<MDB_dbi, 4> fromindexdbi{};
  std::array<MDB_dbi, 4> toindexdbi{};

  index = 0;

  for (const std::string dbname : {"domains", "keydata", "tsig", "metadata"}) {
    std::string fdbname = dbname + "_0";
    std::cerr << "migrating " << dbname << std::endl;
    std::string tdbname = dbname + "_v5_0";

    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
    if (int retCode = MDBDbi::mdb_dbi_open(txn, fdbname.c_str(), 0, &fromindexdbi[index]); retCode != 0) {
      mdb_txn_abort(txn);
      mdb_env_close(env);
      throw std::runtime_error("mdb_dbi_open indexdbi failed: " + MDBError(retCode));
    }

    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
    if (int retCode = MDBDbi::mdb_dbi_open(txn, tdbname.c_str(), MDB_CREATE, &toindexdbi[index]); retCode != 0) {
      // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
      mdb_dbi_close(env, fromindexdbi[index]);
      mdb_txn_abort(txn);
      mdb_env_close(env);
      throw std::runtime_error("mdb_dbi_open indexdbi target failed: " + MDBError(retCode));
    }

    try {
      // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
      copyIndexDBI(txn, fromindexdbi[index], toindexdbi[index]);
    }
    catch (std::exception& e) {
      // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
      mdb_dbi_close(env, toindexdbi[index]);
      // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
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

  MDB_dbi dbi = 0;

  // finally, migrate the pdns db
  if (int retCode = MDBDbi::mdb_dbi_open(txn, "pdns", 0, &dbi); retCode != 0) {
    mdb_txn_abort(txn);
    mdb_env_close(env);
    throw std::runtime_error("mdb_dbi_open pdns failed: " + MDBError(retCode));
  }

  MDB_val key;
  MDB_val data;

  std::string header(LMDBLS::LS_MIN_HEADER_SIZE, '\0');

  for (const std::string keyname : {"schemaversion", "shards"}) {
    cerr << "migrating pdns." << keyname << endl;

    key.mv_data = (char*)keyname.c_str();
    key.mv_size = keyname.size();

    if (int retCode = mdb_get(txn, dbi, &key, &data); retCode != 0) {
      throw std::runtime_error("mdb_get pdns.shards failed: " + MDBError(retCode));
    }

    if (data.mv_size != sizeof(uint32_t)) {
      throw std::runtime_error("got non-uint32_t key");
    }

    uint32_t value = 0;
    memcpy((void*)&value, data.mv_data, sizeof(uint32_t));

    value = htonl(value);
    if (keyname == "schemaversion") {
      value = htonl(5);
    }

    std::string sdata(static_cast<char*>(data.mv_data), data.mv_size);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-cstyle-cast)
    std::string stdata = header + std::string((char*)&value, sizeof(uint32_t));

    MDB_val tdata;

    tdata.mv_data = (char*)stdata.c_str();
    tdata.mv_size = stdata.size();

    if (int retCode = mdb_put(txn, dbi, &key, &tdata, 0); retCode != 0) {
      throw std::runtime_error("mdb_put failed: " + MDBError(retCode));
    }
  }

  for (const std::string keyname : {"uuid"}) {
    cerr << "migrating pdns." << keyname << endl;

    key.mv_data = (char*)keyname.c_str();
    key.mv_size = keyname.size();

    if (int retCode = mdb_get(txn, dbi, &key, &data); retCode != 0) {
      throw std::runtime_error("mdb_get pdns.shards failed: " + MDBError(retCode));
    }

    std::string sdata((char*)data.mv_data, data.mv_size);

    std::string stdata = header + sdata;

    MDB_val tdata;

    tdata.mv_data = (char*)stdata.c_str();
    tdata.mv_size = stdata.size();

    if (int retCode = mdb_put(txn, dbi, &key, &tdata, 0); retCode != 0) {
      throw std::runtime_error("mdb_put failed: " + MDBError(retCode));
    }
  }

  for (int i = 0; i < 4; i++) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
    mdb_drop(txn, fromtypeddbi[i], 1);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
    mdb_drop(txn, fromindexdbi[i], 1);
  }

  cerr << "txn commit=" << mdb_txn_commit(txn) << endl;

  for (int i = 0; i < 4; i++) {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
    mdb_dbi_close(env, totypeddbi[i]);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-constant-array-index)
    mdb_dbi_close(env, toindexdbi[i]);
  }
  mdb_env_close(env);

  cerr << "migration done" << endl;
  return true;
}

bool LMDBBackend::upgradeToSchemav6(std::string& /* filename */, uint32_t /* currentSchemaVersion */, uint32_t /* shardCount */)
{
  // a v6 reader can read v5 databases just fine
  // so this function currently does nothing
  // - except rely on the caller to write '6' to pdns.schemaversion,
  // as a v5 reader will be unable to handle domain objects once we've touched them
  return true;
}

// Serial number cache

// Retrieve the transient domain info for the given domain, if any
bool LMDBBackend::TransientDomainInfoCache::get(domainid_t domainid, TransientDomainInfo& data) const
{
  if (auto iter = d_data.find(domainid); iter != d_data.end()) {
    data = iter->second;
    return true;
  }
  return false;
}

// Remove the transient domain info for the given domain
void LMDBBackend::TransientDomainInfoCache::remove(domainid_t domainid)
{
  if (auto iter = d_data.find(domainid); iter != d_data.end()) {
    d_data.erase(iter);
  }
}

// Create or update the transient domain info for the given domain
void LMDBBackend::TransientDomainInfoCache::update(domainid_t domainid, const TransientDomainInfo& data)
{
  d_data.insert_or_assign(domainid, data);
}

// Return the contents of the first element and remove it
bool LMDBBackend::TransientDomainInfoCache::pop(domainid_t& domainid, TransientDomainInfo& data)
{
  auto iter = d_data.begin();
  if (iter == d_data.end()) {
    return false;
  }
  domainid = iter->first;
  data = iter->second;
  (void)d_data.erase(iter);
  return true;
}

SharedLockGuarded<LMDBBackend::TransientDomainInfoCache> LMDBBackend::s_transient_domain_info;

LMDBBackend::LMDBBackend(const std::string& suffix)
{
  // overlapping domain ids in combination with relative names are a recipe for disaster
  if (!suffix.empty()) {
    throw std::runtime_error("LMDB backend does not support multiple instances");
  }

  d_views = ::arg().mustDo("views"); // This is a global setting

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

  d_mapsize_main = d_mapsize_shards = 0;
  try {
    d_mapsize_main = std::stoll(getArg("map-size"));
  }
  catch (const std::exception& e) {
    throw std::runtime_error(std::string("Unable to parse the 'map-size' LMDB value: ") + e.what());
  }
  try {
    d_mapsize_shards = std::stoll(getArg("shards-map-size"));
  }
  catch (const std::exception& e) {
    throw std::runtime_error(std::string("Unable to parse the 'shards-map-size' LMDB value: ") + e.what());
  }
  if (d_mapsize_shards == 0) {
    // Old configuration with only one settings for main and shards.
    d_mapsize_shards = d_mapsize_main;
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

  // The current state of this code only supports one schema version and
  // requires users to update their schema if outdated.
  d_currentschema = SCHEMAVERSION;

  bool opened = false;

  if (s_first) {
    auto lock = std::scoped_lock(s_lmdbStartupLock);
    if (s_first) {
      auto filename = getArg("filename");

      auto [currentSchemaVersion, shardCount] = getSchemaVersionAndShards(filename);
      // std::cerr<<"current schema version: "<<currentSchemaVersion<<", shards="<<shardCount<<std::endl;

      if (getArgAsNum("schema-version") != SCHEMAVERSION) {
        throw std::runtime_error("This version of the lmdbbackend only supports schema version 6. Configuration demands a lower version. Not starting up.");
      }

      if (currentSchemaVersion > 0 && currentSchemaVersion < 3) {
        throw std::runtime_error("this version of the lmdbbackend can only upgrade from schema v3 and up. Upgrading from older schemas is not supported.");
      }

      if (currentSchemaVersion == 0) {
        // no database is present yet, we can just create them
        currentSchemaVersion = 6;
      }

      if (currentSchemaVersion == 3 || currentSchemaVersion == 4) {
        if (!upgradeToSchemav5(filename, currentSchemaVersion, shardCount)) {
          throw std::runtime_error("Failed to perform LMDB schema version upgrade from v4 to v5");
        }
        currentSchemaVersion = 5;
      }

      if (currentSchemaVersion == 5) {
        if (!upgradeToSchemav6(filename, currentSchemaVersion, shardCount)) {
          throw std::runtime_error("Failed to perform LMDB schema version upgrade from v5 to v6");
        }
        currentSchemaVersion = 6;
      }

      if (currentSchemaVersion != 6) {
        throw std::runtime_error("Somehow, we are not at schema version 6. Giving up");
      }

      openAllTheDatabases();
      opened = true;
      auto pdnsdbi = d_tdomains->getEnv()->openDB("pdns", MDB_CREATE);

      auto txn = d_tdomains->getEnv()->getRWTransaction();

      const auto configShardsTemp = atoi(getArg("shards").c_str());
      if (configShardsTemp < 0) {
        throw std::runtime_error("a negative shards value is not supported");
      }
      if (configShardsTemp == 0) {
        throw std::runtime_error("a shards value of 0 is not supported");
      }
      const auto configShards = static_cast<uint32_t>(configShardsTemp);

      MDBOutVal shards{};
      if (txn->get(pdnsdbi, "shards", shards) == 0) {
        s_shards = shards.get<uint32_t>();

        if (mustDo("lightning-stream") && s_shards != 1) {
          throw std::runtime_error("running with Lightning Stream support enabled requires a database with exactly 1 shard");
        }

        if (s_shards != configShards) {
          g_log << Logger::Warning
                << "Note: configured number of lmdb shards ("
                << atoi(getArg("shards").c_str())
                << ") is different from on-disk ("
                << s_shards
                << "). Using on-disk shard number"
                << endl;
        }
      }
      else {
        s_shards = configShards;
        txn->put(pdnsdbi, "shards", s_shards);
      }

      MDBOutVal gotuuid{};
      if (txn->get(pdnsdbi, "uuid", gotuuid) != 0) {
        const auto uuid = getUniqueID();
        const string uuids(uuid.begin(), uuid.end());
        txn->put(pdnsdbi, "uuid", uuids);
      }

      MDBOutVal _schemaversion{};
      if (txn->get(pdnsdbi, "schemaversion", _schemaversion) != 0 || _schemaversion.get<uint32_t>() != currentSchemaVersion) {
        txn->put(pdnsdbi, "schemaversion", currentSchemaVersion);
      }
      txn->commit();

      s_first = false;
    }
  }

  if (!opened) {
    openAllTheDatabases();
  }
  d_trecords.resize(s_shards);
  d_dolog = ::arg().mustDo("query-logging");
}

LMDBBackend::~LMDBBackend()
{
  // LMDB internals require that, if we have multiple transactions active,
  // we destroy them in the reverse order of their creation, thus we can't
  // let the default destructor take care of d_rotxn and d_rwtxn.
  if (d_txnorder) {
    // RO transaction more recent than RW transaction
    d_rotxn.reset();
    d_rwtxn.reset();
  }
  else {
    // RW transaction more recent than RO transaction
    d_rwtxn.reset();
    d_rotxn.reset();
  }
}

void LMDBBackend::openAllTheDatabases()
{
  d_tdomains = std::make_shared<tdomains_t>(getMDBEnv(getArg("filename").c_str(), MDB_NOSUBDIR | MDB_NORDAHEAD | d_asyncFlag, 0600, d_mapsize_main), "domains_v5");
  d_tmeta = std::make_shared<tmeta_t>(d_tdomains->getEnv(), "metadata_v5");
  d_tkdb = std::make_shared<tkdb_t>(d_tdomains->getEnv(), "keydata_v5");
  d_ttsig = std::make_shared<ttsig_t>(d_tdomains->getEnv(), "tsig_v5");
  d_tnetworks = d_tdomains->getEnv()->openDB("networks_v6", MDB_CREATE);
  d_tviews = d_tdomains->getEnv()->openDB("views_v6", MDB_CREATE);
}

unsigned int LMDBBackend::getCapabilities()
{
  unsigned int caps = CAP_DNSSEC | CAP_DIRECT | CAP_LIST | CAP_CREATE | CAP_SEARCH;
  if (d_views) {
    caps |= CAP_VIEWS;
  }
  return caps;
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
      ar & g.toDNSStringLC();
    }
  }

  template <class Archive>
  void load(Archive& ar, DNSName& g, const unsigned int /* version */)
  {
    string tmp;
    ar & tmp;
    if (tmp.empty()) {
      g = DNSName();
    }
    else {
      g = DNSName(tmp.c_str(), tmp.size(), 0, false);
    }
  }

  template <class Archive>
  void save(Archive& arc, const ZoneName& zone, const unsigned int /* version */)
  {
    arc & zone.operator const DNSName&();
    arc & zone.getVariant();
  }

  template <class Archive>
  void load(Archive& arc, ZoneName& zone, const unsigned int version)
  {
    if (version == 0) { // for schemas up to 5, ZoneName serialized as DNSName
      std::string tmp{};
      arc & tmp;
      if (tmp.empty()) {
        zone = ZoneName();
      }
      else {
        zone = ZoneName(DNSName(tmp.c_str(), tmp.size(), 0, false));
      }
      return;
    }
    DNSName tmp;
    std::string variant{};
    arc & tmp;
    arc & variant;
    zone = ZoneName(tmp, variant);
  }

  template <class Archive>
  void save(Archive& ar, const DomainInfo& g, const unsigned int /* version */)
  {
    ar & g.zone;
    ar & g.last_check;
    ar & g.account;
    ar & g.primaries;
    ar& static_cast<uint32_t>(g.id);
    ar & g.notified_serial;
    ar & g.kind;
    ar & g.options;
    ar & g.catalog;
  }

  template <class Archive>
  void load(Archive& ar, DomainInfo& g, const unsigned int version)
  {
    if (version >= 2) {
      ar & g.zone;
    }
    else {
      DNSName tmp;
      ar & tmp;
      new (&g.zone) ZoneName(tmp);
    }
    ar & g.last_check;
    ar & g.account;
    ar & g.primaries;
    uint32_t domainId{0};
    ar & domainId;
    g.id = static_cast<domainid_t>(domainId);
    ar & g.notified_serial;
    ar & g.kind;
    switch (version) {
    case 0:
      // These fields did not exist.
      g.options.clear();
      g.catalog.clear();
      break;
    case 1:
      // These fields did exist, but catalog as DNSName only.
      ar & g.options;
      {
        DNSName tmp;
        ar & tmp;
        g.catalog = ZoneName(tmp);
      }
      break;
    default:
      // These fields exist, with catalog as ZoneName.
      ar & g.options;
      ar & g.catalog;
      break;
    }
  }

  template <class Archive>
  void serialize(Archive& ar, LMDBBackend::DomainMeta& g, const unsigned int /* version */)
  {
    ar & g.domain & g.key & g.value;
  }

  template <class Archive>
  void save(Archive& ar, const LMDBBackend::KeyDataDB& g, const unsigned int /* version */)
  {
    ar & g.domain & g.content & g.flags & g.active & g.published;
  }

  template <class Archive>
  void load(Archive& ar, LMDBBackend::KeyDataDB& g, const unsigned int version)
  {
    ar & g.domain & g.content & g.flags & g.active;
    if (version >= 1) {
      ar & g.published;
    }
    else {
      g.published = true;
    }
  }

  template <class Archive>
  void serialize(Archive& ar, TSIGKey& g, const unsigned int /* version */)
  {
    ar & g.name;
    ar & g.algorithm; // this is the ordername
    ar & g.key;
  }

} // namespace serialization
} // namespace boost

BOOST_SERIALIZATION_SPLIT_FREE(DNSName);
BOOST_SERIALIZATION_SPLIT_FREE(ZoneName);
BOOST_SERIALIZATION_SPLIT_FREE(LMDBBackend::KeyDataDB);
BOOST_SERIALIZATION_SPLIT_FREE(DomainInfo);
BOOST_IS_BITWISE_SERIALIZABLE(ComboAddress);

// Resource records are serialized in the following format:
// - length of record content (16 bits)
// - record content (variable size)
// - ttl (32 bits)
// - auth flag (8 bits)
// - disabled flag (8 bits)
// - hasOrderName flag (8 bits)

// The following constants try and make the logic in the following few routines
// less obscure and more future-proof.
constexpr size_t serialize_prefix_size = sizeof(uint16_t); // 2
constexpr size_t serialize_trailing_size = sizeof(uint32_t) + 3; // 7
constexpr size_t serialize_minimum_size = serialize_prefix_size + serialize_trailing_size;
constexpr size_t serialize_offset_ttl = 0;
constexpr size_t serialize_offset_auth = serialize_offset_ttl + sizeof(uint32_t);
constexpr size_t serialize_offset_disabled = serialize_offset_auth + sizeof(char);
constexpr size_t serialize_offset_ordername = serialize_offset_disabled + sizeof(char);

template <>
void serializeToBuffer(std::string& buffer, const LMDBBackend::LMDBResourceRecord& value)
{
  // Data size of the resource record.
  uint16_t len = value.content.length();

  // Reserve space to store the size of the resource record + the content of the resource
  // record + a few other things.
  buffer.reserve(buffer.size() + sizeof(len) + len + sizeof(value.ttl) + sizeof(value.auth) + sizeof(value.disabled) + sizeof(value.hasOrderName));

  // Store the size of the resource record (in host order).
  // NOLINTNEXTLINE.
  buffer.append((const char*)&len, sizeof(len));

  // Store the contents of the resource record.
  buffer.append(value.content);

  // The few other things.
  // NOLINTNEXTLINE.
  buffer.append((const char*)&value.ttl, sizeof(value.ttl));
  buffer.append(1, (char)value.auth);
  buffer.append(1, (char)value.disabled);
  buffer.append(1, (char)value.hasOrderName);
}

template <>
void serializeToBuffer(std::string& buffer, const vector<LMDBBackend::LMDBResourceRecord>& value)
{
  for (const auto& lrr : value) {
    serializeToBuffer(buffer, lrr);
  }
}

static inline size_t deserializeRRFromBuffer(const string_view& str, LMDBBackend::LMDBResourceRecord& lrr)
{
  const auto* data = str.data();
  uint16_t len;
  memcpy(&len, data, sizeof(len));
  if (str.size() < serialize_prefix_size + len + serialize_trailing_size) {
    return 0;
  }
  // NOLINTBEGIN(cppcoreguidelines-pro-bounds-pointer-arithmetic): due to the above size check, this is safe
  data += sizeof(len);
  lrr.content.assign(data, len); // len bytes
  data += len;
  memcpy(&lrr.ttl, data, sizeof(uint32_t));
  data += sizeof(uint32_t);
  lrr.auth = *data++ != 0;
  lrr.disabled = *data++ != 0;
  lrr.hasOrderName = *data++ != 0;
  // NOLINTEND(cppcoreguidelines-pro-bounds-pointer-arithmetic)
  lrr.wildcardname.clear();

  return data - str.data();
}

template <>
void deserializeFromBuffer(const string_view& buffer, LMDBBackend::LMDBResourceRecord& value)
{
  if (buffer.size() >= serialize_minimum_size) {
    deserializeRRFromBuffer(buffer, value);
  }
}

template <>
void deserializeFromBuffer(const string_view& buffer, vector<LMDBBackend::LMDBResourceRecord>& value)
{
  auto str_copy = buffer;
  while (str_copy.size() >= serialize_minimum_size) {
    LMDBBackend::LMDBResourceRecord lrr;
    auto rrLength = deserializeRRFromBuffer(str_copy, lrr);
    if (rrLength == 0) {
      break;
    }
    value.emplace_back(lrr);
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
  return DNSRecordContent::deserialize(qname, qtype, content, QClass::IN, true);
}

// For the few places where we are only interested in the hasOrderName field,
// this cheap routine is faster than doing:
// {
//   LMDBResourceRecord lrr;
//   deserializeFromBuffer(buffer, lrr);
//   return lrr.hasOrderName;
// }
static bool peekAtHasOrderName(const string_view& buffer)
{
  uint16_t len{0};
  memcpy(&len, buffer.data(), sizeof(uint16_t));
  bool hasOrderName = buffer[serialize_prefix_size + len + serialize_offset_ordername] != 0;
  return hasOrderName;
}

// Similar to the above, but for the auth field.
static bool peekAtAuth(const string_view& buffer)
{
  uint16_t len{0};
  memcpy(&len, buffer.data(), sizeof(uint16_t));
  bool auth = buffer[serialize_prefix_size + len + serialize_offset_auth] != 0;
  return auth;
}

// Similar to the above, but for the ttl.
static uint32_t peekAtTtl(const string_view& buffer)
{
  uint16_t len{0};
  memcpy(&len, buffer.data(), sizeof(uint16_t));
  uint32_t ttl{0};
  memcpy(&ttl, buffer.data() + serialize_prefix_size + len + serialize_offset_ttl, sizeof(uint32_t));
  return ttl;
}

/* A note on the design.

   If you ask a question without a zone id (this can be the case for lookup(),
   and of course also for startTransaction if you don't want to delete the
   domain contents), we lookup the best zone id for you, and answer from that.

   The index we use is "zoneid,canonical relative name". This index is also used
   for AXFR.

   Note - domain_id, name and type are ONLY present on the index!
*/

#if BOOST_VERSION >= 106100
#define StringView string_view
#else
#define StringView string
#endif

void LMDBBackend::deleteDomainRecords(RecordsRWTransaction& txn, const std::string& match, QType qtype)
{
  auto cursor = txn.txn->getCursor(txn.db->dbi);
  MDBOutVal key{};
  MDBOutVal val{};

  if (cursor.prefix(match, key, val) == 0) {
    do {
      if (qtype == QType::ANY || compoundOrdername::getQType(key.getNoStripHeader<StringView>()) == qtype) {
        cursor.del(key);
      }
    } while (cursor.next(key, val) == 0);
  }
}

bool LMDBBackend::findDomain(const ZoneName& domain, DomainInfo& info) const
{
  auto rotxn = d_tdomains->getROTransaction();
  auto domain_id = rotxn.get<0>(domain, info);
  if (domain_id == 0) {
    return false;
  }
  info.id = static_cast<domainid_t>(domain_id);
  return true;
}

bool LMDBBackend::findDomain(domainid_t domainid, DomainInfo& info) const
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
  // Update the DomainInfo values if we have cached data in memory.
  if (!d_write_notification_update) {
    auto container = s_transient_domain_info.read_lock();
    TransientDomainInfo tdi;
    if (container->get(info.id, tdi)) {
      info.notified_serial = tdi.notified_serial;
      info.last_check = tdi.last_check;
    }
  }
}

void LMDBBackend::writeDomainInfo(const DomainInfo& info)
{
  if (!d_write_notification_update) {
    auto container = s_transient_domain_info.write_lock();
    TransientDomainInfo tdi;
    if (container->get(info.id, tdi)) {
      // Only remove the in-memory value if it has not been modified since the
      // DomainInfo data was set up.
      if (tdi.notified_serial == info.notified_serial && tdi.last_check == info.last_check) {
        container->remove(info.id);
      }
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

bool LMDBBackend::startTransaction(const ZoneName& domain, domainid_t domain_id)
{
  // cout <<"startTransaction("<<domain<<", "<<domain_id<<")"<<endl;
  domainid_t real_id = domain_id;
  if (real_id == UnknownDomainID) {
    DomainInfo info;
    if (!findDomain(domain, info)) {
      return false;
    }
    real_id = info.id;
  }
  if (d_rwtxn) {
    throw DBException("Attempt to start a transaction while one was open already");
  }
  d_rwtxn = getRecordsRWTransaction(real_id);
  d_txnorder = false;

  d_transactiondomain = domain;
  d_transactiondomainid = real_id;
  if (domain_id != UnknownDomainID) {
    compoundOrdername order;
    string match = order(domain_id);
    LMDBBackend::deleteDomainRecords(*d_rwtxn, match);
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

// Remove the NSEC3 records pair found at the given `qname', if any.
void LMDBBackend::deleteNSEC3RecordPair(const std::shared_ptr<RecordsRWTransaction>& txn, domainid_t domain_id, const DNSName& qname)
{
  compoundOrdername co; // NOLINT(readability-identifier-length)
  MDBOutVal val{};

  auto key = co(domain_id, qname, QType::NSEC3);
  if (txn->txn->get(txn->db->dbi, key, val) == 0) {
    LMDBResourceRecord lrr;
    deserializeFromBuffer(val.get<string_view>(), lrr);
    DNSName ordername(lrr.content.c_str(), lrr.content.size(), 0, false);
    txn->txn->del(txn->db->dbi, co(domain_id, ordername, QType::NSEC3));
    txn->txn->del(txn->db->dbi, key);
  }
}

// Write a pair of NSEC3 records referencing each other, between `qname' and
// `ordername'.
void LMDBBackend::writeNSEC3RecordPair(const std::shared_ptr<RecordsRWTransaction>& txn, domainid_t domain_id, const DNSName& qname, const DNSName& ordername)
{
  // We can only write one NSEC3 record par qname; do not attempt to write
  // records pointing to ourselves, as only the last record of the pair would
  // end up in the database.
  if (ordername == qname) {
    return;
  }

  compoundOrdername co; // NOLINT(readability-identifier-length)

  // Check for an existing NSEC3 record. If one exists, either it points to the
  // same ordername and we have nothing to do, or the ordername has changed and
  // we need to remove the about-to-become-dangling back chain record.
  MDBOutVal val{};
  if (txn->txn->get(txn->db->dbi, co(domain_id, qname, QType::NSEC3), val) == 0) {
    LMDBResourceRecord lrr;
    deserializeFromBuffer(val.get<string_view>(), lrr);
    DNSName prevordername(lrr.content.c_str(), lrr.content.size(), 0, false);
    if (prevordername == ordername) {
      return; // nothing to do! (assuming the other record also exists)
    }
    txn->txn->del(txn->db->dbi, co(domain_id, prevordername, QType::NSEC3));
  }

  LMDBResourceRecord lrr;
  lrr.auth = false;

  // Write ordername -> qname back chain record with ttl set to 0
  lrr.ttl = 0;
  lrr.content = qname.toDNSStringLC();
  std::string ser = MDBRWTransactionImpl::stringWithEmptyHeader();
  serializeToBuffer(ser, lrr);
  txn->txn->put_header_in_place(txn->db->dbi, co(domain_id, ordername, QType::NSEC3), ser);

  // Write qname -> ordername forward chain record with ttl set to 1
  lrr.ttl = 1;
  lrr.content = ordername.toDNSString();
  ser = MDBRWTransactionImpl::stringWithEmptyHeader();
  serializeToBuffer(ser, lrr);
  txn->txn->put_header_in_place(txn->db->dbi, co(domain_id, qname, QType::NSEC3), ser);
}

// Check if the only records found for this particular name are a single NSEC3
// record. (in which case there is no actual data for that qname and that
// record needs to be deleted)
bool LMDBBackend::hasOrphanedNSEC3Record(MDBRWCursor& cursor, domainid_t domain_id, const DNSName& qname)
{
  compoundOrdername co; // NOLINT(readability-identifier-length)
  bool seenNSEC3{false};
  bool seenOther{false};
  MDBOutVal key{};
  MDBOutVal val{};

  if (cursor.prefix(co(domain_id, qname), key, val) == 0) {
    do {
      if (compoundOrdername::getQType(key.getNoStripHeader<StringView>()) == QType::NSEC3) {
        seenNSEC3 = true;
      }
      else {
        seenOther = true;
      }
      if (seenNSEC3 && seenOther) {
        break;
      }
    } while (cursor.next(key, val) == 0);
  }
  return seenNSEC3 && !seenOther;
}

// d_rwtxn must be set here
bool LMDBBackend::feedRecord(const DNSResourceRecord& r, const DNSName& ordername, bool ordernameIsNSEC3)
{
  LMDBResourceRecord lrr(r);
  lrr.qname.makeUsRelative(d_transactiondomain);
  lrr.content = serializeContent(lrr.qtype.getCode(), r.qname, lrr.content);
  // Note that this is safe, as ordernameIsNSEC3 will NOT be set if NSEC3
  // but narrow.
  lrr.hasOrderName = ordernameIsNSEC3 && !ordername.empty();

  compoundOrdername co;
  string matchName = co(lrr.domain_id, lrr.qname, lrr.qtype.getCode());

  string rrs = MDBRWTransactionImpl::stringWithEmptyHeader();
  MDBOutVal _rrs;
  if (!d_rwtxn->txn->get(d_rwtxn->db->dbi, matchName, _rrs)) {
    rrs.append(_rrs.get<string>());
  }
  serializeToBuffer(rrs, lrr);
  d_rwtxn->txn->put_header_in_place(d_rwtxn->db->dbi, matchName, rrs);

  if (lrr.hasOrderName) {
    writeNSEC3RecordPair(d_rwtxn, lrr.domain_id, lrr.qname, ordername);
  }
  return true;
}

bool LMDBBackend::feedEnts(domainid_t domain_id, map<DNSName, bool>& nonterm)
{
  LMDBResourceRecord lrr;
  lrr.ttl = 0;
  compoundOrdername co;
  for (const auto& nt : nonterm) {
    lrr.qname = nt.first.makeRelative(d_transactiondomain);
    lrr.auth = nt.second;
    lrr.hasOrderName = false;

    std::string ser = MDBRWTransactionImpl::stringWithEmptyHeader();
    serializeToBuffer(ser, lrr);
    d_rwtxn->txn->put_header_in_place(d_rwtxn->db->dbi, co(domain_id, lrr.qname, QType::ENT), ser);
  }
  return true;
}

bool LMDBBackend::feedEnts3(domainid_t domain_id, const DNSName& domain, map<DNSName, bool>& nonterm, const NSEC3PARAMRecordContent& ns3prc, bool narrow)
{
  DNSName ordername;
  LMDBResourceRecord lrr;
  compoundOrdername co;
  for (const auto& nt : nonterm) {
    lrr.qname = nt.first.makeRelative(domain);
    lrr.ttl = 0;
    lrr.auth = nt.second;
    lrr.hasOrderName = lrr.auth && !narrow;
    std::string ser = MDBRWTransactionImpl::stringWithEmptyHeader();
    serializeToBuffer(ser, lrr);
    d_rwtxn->txn->put_header_in_place(d_rwtxn->db->dbi, co(domain_id, lrr.qname, QType::ENT), ser);

    if (lrr.hasOrderName) {
      ordername = DNSName(toBase32Hex(hashQNameWithSalt(ns3prc, nt.first)));
      writeNSEC3RecordPair(d_rwtxn, domain_id, lrr.qname, ordername);
    }
  }
  return true;
}

// might be called within a transaction, might also be called alone
// NOLINTNEXTLINE(readability-identifier-length)
bool LMDBBackend::replaceRRSet(domainid_t domain_id, const DNSName& qname, const QType& qt, const vector<DNSResourceRecord>& rrset)
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

  DNSName relative = qname.makeRelative(info.zone);
  compoundOrdername co;
  string match;
  if (qt.getCode() == QType::ANY) {
    // Check for an existing NSEC3 record. If one exists, we need to also
    // remove the back chain record.
    deleteNSEC3RecordPair(txn, domain_id, relative);
    match = co(domain_id, relative);
    deleteDomainRecords(*txn, match);
    // Update key if insertions are to follow
    if (!rrset.empty()) {
      match = co(domain_id, relative, rrset.front().qtype.getCode());
    }
  }
  else {
    if (qt.getCode() == QType::NSEC3) {
      deleteNSEC3RecordPair(txn, domain_id, relative);
    }
    else {
      auto cursor = txn->txn->getCursor(txn->db->dbi);
      MDBOutVal key{};
      MDBOutVal val{};
      bool hadOrderName{false};
      match = co(domain_id, relative, qt.getCode());
      // There should be at most one exact match here.
      if (cursor.find(match, key, val) == 0) {
        hadOrderName = peekAtHasOrderName(val.get<string_view>());
        cursor.del(key);
      }
      // If we are not going to add any new records, check if there are any
      // remaining records for this qname, ignoring NSEC3 chain records. If
      // there aren't any, yet there is an NSEC3 record, delete the NSEC3 chain
      // pair as well.
      if (rrset.empty()) {
        if (hadOrderName && hasOrphanedNSEC3Record(cursor, domain_id, relative)) {
          deleteNSEC3RecordPair(txn, domain_id, relative);
        }
      }
    }
  }

  if (!rrset.empty()) {
    vector<LMDBResourceRecord> adjustedRRSet;
    adjustedRRSet.reserve(rrset.size());
    for (const auto& rr : rrset) {
      LMDBResourceRecord lrr(rr);
      lrr.content = serializeContent(lrr.qtype.getCode(), lrr.qname, lrr.content);
      lrr.qname.makeUsRelative(info.zone);

      adjustedRRSet.emplace_back(lrr);
    }
    std::string ser = MDBRWTransactionImpl::stringWithEmptyHeader();
    serializeToBuffer(ser, adjustedRRSet);
    txn->txn->put_header_in_place(txn->db->dbi, match, ser);
  }

  if (needCommit)
    txn->txn->commit();

  return true;
}

// NOLINTNEXTLINE(readability-identifier-length)
bool LMDBBackend::replaceComments([[maybe_unused]] domainid_t domain_id, [[maybe_unused]] const DNSName& qname, [[maybe_unused]] const QType& qt, const vector<Comment>& comments)
{
  // if the vector is empty, good, that's what we do here (LMDB does not store comments)
  // if it's not, report failure
  return comments.empty();
}

// FIXME: this is not very efficient
static DNSName keyUnconv(std::string& instr)
{
  // instr is now com0example0
  vector<string> labels;
  boost::split(labels, instr, [](char chr) { return chr == '\0'; });

  // we get a spurious empty label at the end, drop it
  labels.resize(labels.size() - 1);

  if (labels.size() == 1 && labels[0].empty()) {
    // this is the root
    return g_rootdnsname;
  }

  DNSName tmp;

  while (!labels.empty()) {
    tmp.appendRawLabel(labels.back());
    labels.pop_back();
  }
  return tmp;
}

static std::string makeBadDataExceptionMessage(const std::string& where, std::exception& exc, MDBOutVal& key, MDBOutVal& val)
{
  ostringstream msg;
  msg << "during " << where << ", got exception (" << exc.what() << "), ";
  msg << "key: " << makeHexDump(key.getNoStripHeader<string>()) << ", ";
  msg << "value: " << makeHexDump(val.get<string>());

  return msg.str();
}

void LMDBBackend::viewList(vector<string>& result)
{
  auto txn = d_tdomains->getEnv()->getROTransaction();

  auto cursor = txn->getROCursor(d_tviews);

  MDBOutVal key{}; // <view, dnsname>
  MDBOutVal val{}; // <variant>

  auto ret = cursor.first(key, val);

  if (ret == MDB_NOTFOUND) {
    return;
  }

  do {
    string view;
    string zone;
    try {
      std::tie(view, zone) = splitField(key.getNoStripHeader<string>(), '\x0');
      auto variant = val.get<string>();
      result.push_back(view);
    }
    catch (std::exception& e) {
      throw PDNSException(makeBadDataExceptionMessage("viewList", e, key, val));
    }

    string inkey{view + string(1, (char)1)};
    MDBInVal bound{inkey};
    ret = cursor.lower_bound(bound, key, val); // this should use some lower bound thing to skip to the next view, also avoiding duplicates in `result`
  } while (ret != MDB_NOTFOUND);
}

void LMDBBackend::viewListZones(const string& inview, vector<ZoneName>& result)
{
  result.clear();

  auto txn = d_tdomains->getEnv()->getROTransaction();

  auto cursor = txn->getROCursor(d_tviews);

  string inkey{inview + string(1, (char)0)};
  MDBInVal prefix{inkey};
  MDBOutVal key{}; // <view, dnsname>
  MDBOutVal val{}; // <variant>

  auto ret = cursor.prefix(prefix, key, val);

  if (ret == MDB_NOTFOUND) {
    return;
  }

  do {
    try {
      auto [view, _zone] = splitField(key.getNoStripHeader<string>(), '\x0');
      auto variant = val.get<string>();
      auto zone = keyUnconv(_zone);
      result.emplace_back(ZoneName(zone, variant));
    }
    catch (std::exception& e) {
      throw PDNSException(makeBadDataExceptionMessage("viewListZones", e, key, val));
    }

    ret = cursor.next(key, val);
  } while (ret != MDB_NOTFOUND);
}

// TODO: make this add-or-del to reduce code duplication?
bool LMDBBackend::viewAddZone(const string& view, const ZoneName& zone)
{
  auto txn = d_tdomains->getEnv()->getRWTransaction();

  string key = view + string(1, (char)0) + keyConv(zone.operator const DNSName&());
  std::string val = MDBRWTransactionImpl::stringWithEmptyHeader();
  val.append(zone.getVariant()); // variant goes here

  txn->put_header_in_place(d_tviews, key, val);
  txn->commit();

  return true;
}

bool LMDBBackend::viewDelZone(const string& view, const ZoneName& zone)
{
  auto txn = d_tdomains->getEnv()->getRWTransaction();

  string key = view + string(1, (char)0) + keyConv(zone.operator const DNSName&());
  // string val = "foo"; // variant goes here

  txn->del(d_tviews, key);
  txn->commit();

  return true;
}

bool LMDBBackend::networkSet(const Netmask& net, std::string& view)
{
  auto txn = d_tdomains->getEnv()->getRWTransaction();

  if (view.empty()) {
    txn->del(d_tnetworks, net.toByteString());
  }
  else {
    txn->put(d_tnetworks, net.toByteString(), view);
  }
  txn->commit();

  return true;
}

bool LMDBBackend::networkList(vector<pair<Netmask, string>>& networks)
{
  networks.clear();

  auto txn = d_tdomains->getEnv()->getROTransaction();

  auto cursor = txn->getROCursor(d_tnetworks);

  MDBOutVal netval{};
  MDBOutVal viewval{};

  auto ret = cursor.first(netval, viewval);

  if (ret == MDB_NOTFOUND) {
    return true;
  }

  do {
    try {
      auto net = Netmask(netval.getNoStripHeader<string>(), Netmask::byteString);
      auto view = viewval.get<string>();
      networks.emplace_back(std::make_pair(net, view));
    }
    catch (std::exception& e) {
      throw PDNSException(makeBadDataExceptionMessage("networkList", e, netval, viewval));
    }

    ret = cursor.next(netval, viewval);
  } while (ret != MDB_NOTFOUND);

  return true;
}

// tempting to templatize these two functions but the pain is not worth it
// NOLINTNEXTLINE(readability-identifier-length)
std::shared_ptr<LMDBBackend::RecordsRWTransaction> LMDBBackend::getRecordsRWTransaction(domainid_t id)
{
  auto& shard = d_trecords[id % s_shards];
  if (!shard.env) {
    shard.env = getMDBEnv((getArg("filename") + "-" + std::to_string(id % s_shards)).c_str(),
                          MDB_NOSUBDIR | MDB_NORDAHEAD | d_asyncFlag, 0600, d_mapsize_shards);
    shard.dbi = shard.env->openDB("records_v5", MDB_CREATE);
  }
  auto ret = std::make_shared<RecordsRWTransaction>(shard.env->getRWTransaction());
  ret->db = std::make_shared<RecordsDB>(shard);

  return ret;
}

// NOLINTNEXTLINE(readability-identifier-length)
std::shared_ptr<LMDBBackend::RecordsROTransaction> LMDBBackend::getRecordsROTransaction(domainid_t id, const std::shared_ptr<LMDBBackend::RecordsRWTransaction>& rwtxn)
{
  auto& shard = d_trecords[id % s_shards];
  if (!shard.env) {
    if (rwtxn) {
      throw DBException("attempting to start nested transaction without open parent env");
    }
    shard.env = getMDBEnv((getArg("filename") + "-" + std::to_string(id % s_shards)).c_str(),
                          MDB_NOSUBDIR | MDB_NORDAHEAD | d_asyncFlag, 0600, d_mapsize_shards);
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

bool LMDBBackend::deleteDomain(const ZoneName& domain)
{
  if (!d_rwtxn) {
    throw DBException(std::string(__PRETTY_FUNCTION__) + " called without a transaction");
  }

  int transactionDomainId = d_transactiondomainid;
  ZoneName transactionDomain = d_transactiondomain;

  abortTransaction();

  LmdbIdVec idvec;

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
      LmdbIdVec ids;

      txn.get_multi<0>(domain, ids);

      for (auto& _id : ids) {
        txn.del(_id);
      }

      txn.commit();
    }

    { // Remove cryptokeys
      auto txn = d_tkdb->getRWTransaction();
      LmdbIdVec ids;
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
      container->remove(static_cast<domainid_t>(id));
    }
    auto txn = d_tdomains->getRWTransaction();
    txn.del(id);
    txn.commit();
  }

  startTransaction(transactionDomain, transactionDomainId);

  return true;
}

bool LMDBBackend::list(const ZoneName& target, domainid_t domain_id, bool include_disabled)
{
  d_lookupstate.domain = target;
  d_lookupstate.submatch.clear();
  d_lookupstate.includedisabled = include_disabled;

  compoundOrdername order;
  std::string match = order(domain_id);

  lookupStart(domain_id, match, false);
  return true;
}

bool LMDBBackend::listSubZone(const ZoneName& target, domainid_t domain_id)
{
  // 1. from domain_id get base domain name
  DomainInfo info;
  if (!findDomain(domain_id, info)) {
    return false;
  }

  // 2. make target relative to it
  DNSName relqname = target.operator const DNSName&().makeRelative(info.zone);
  if (relqname.empty()) {
    return false;
  }

  // 3. enumerate complete domain, but tell get() to ignore entries which are
  //    not subsets of target
  d_lookupstate.domain = std::move(info.zone);
  d_lookupstate.submatch = std::move(relqname);
  d_lookupstate.includedisabled = true;

  compoundOrdername order;
  std::string match = order(domain_id);

  lookupStart(domain_id, match, false);
  return true;
}

void LMDBBackend::lookupInternal(const QType& type, const DNSName& qdomain, domainid_t zoneId, DNSPacket* /* p */, bool include_disabled)
{
  if (d_dolog) {
    g_log << Logger::Warning << "Got lookup for " << qdomain << "|" << type.toString() << " in zone " << zoneId << endl;
    d_dtime.set();
  }

  DomainInfo info;
  if (zoneId == UnknownDomainID) { // may be the case if coming from lookup()
    ZoneName hunt(qdomain);
    do {
      if (findDomain(hunt, info)) {
        break;
      }
    } while (type != QType::SOA && hunt.chopOff());
    if (info.id == 0) {
      //      cout << "Did not find zone for "<< qdomain<<endl;
      d_lookupstate.reset();
      return;
    }
  }
  else {
    if (!findDomain(zoneId, info)) {
      // cout<<"Could not find a zone with id "<<zoneId<<endl;
      d_lookupstate.reset();
      return;
    }
  }

  DNSName relqname = qdomain.makeRelative(info.zone);
  if (relqname.empty()) {
    return;
  }
  // cout<<"get will look for "<<relqname<< " in zone "<<info.zone<<" with id "<<info.id<<" and type "<<type.toString()<<endl;

  d_lookupstate.domain = std::move(info.zone);
  d_lookupstate.submatch.clear();
  d_lookupstate.includedisabled = include_disabled;

  compoundOrdername order;
  std::string match;
  if (type.getCode() == QType::ANY) {
    match = order(info.id, relqname);
  }
  else {
    match = order(info.id, relqname, type.getCode());
  }

  lookupStart(info.id, match, d_dolog);
}

void LMDBBackend::lookupStart(domainid_t domain_id, const std::string& match, bool dolog)
{
  d_rotxn = getRecordsROTransaction(domain_id, d_rwtxn);
  d_txnorder = true;
  d_lookupstate.cursor = std::make_shared<MDBROCursor>(d_rotxn->txn->getCursor(d_rotxn->db->dbi));

  // Make sure we start with fresh data
  d_lookupstate.rrset.clear();
  d_lookupstate.rrsetpos = 0;

  MDBOutVal key{};
  MDBOutVal val{};
  if (d_lookupstate.cursor->prefix(match, key, val) != 0) {
    d_lookupstate.reset(); // will cause get() to fail
    if (dolog) {
      g_log << Logger::Warning << "Query " << ((long)(void*)this) << ": " << d_dtime.udiffNoReset() << " us to execute (found nothing)" << endl;
    }
    return;
  }

  if (dolog) {
    g_log << Logger::Warning << "Query " << ((long)(void*)this) << ": " << d_dtime.udiffNoReset() << " us to execute" << endl;
  }
}

bool LMDBBackend::getInternal(DNSName& basename, std::string_view& key)
{
  for (;;) {
    if (!d_lookupstate.rrset.empty()) {
      if (++d_lookupstate.rrsetpos >= d_lookupstate.rrset.size()) {
        d_lookupstate.rrset.clear(); // will invalidate lrr
        if (d_lookupstate.cursor && d_lookupstate.cursor->next(d_lookupstate.key, d_lookupstate.val) != 0) {
          // cerr<<"resetting d_lookupstate.cursor 2"<<endl;
          d_lookupstate.reset();
        }
      }
    }

    // std::cerr<<"d_lookupstate.cursor="<<d_lookupstate.cursor<<std::endl;
    if (!d_lookupstate.cursor) {
      d_rotxn.reset();
      return false;
    }

    if (d_lookupstate.rrset.empty()) {
      d_lookupstate.cursor->current(d_lookupstate.key, d_lookupstate.val);

      key = d_lookupstate.key.getNoStripHeader<string_view>();
      QType qtype = compoundOrdername::getQType(key).getCode();

      if (qtype == QType::NSEC3) {
        // Hit a special NSEC3 record, skip it
        if (d_lookupstate.cursor->next(d_lookupstate.key, d_lookupstate.val) != 0) {
          // cerr<<"resetting d_lookupstate.cursor 1"<<endl;
          d_lookupstate.reset();
        }
        continue;
      }

      deserializeFromBuffer(d_lookupstate.val.get<string_view>(), d_lookupstate.rrset);
      d_lookupstate.rrsettime = static_cast<time_t>(LMDBLS::LSgetTimestamp(d_lookupstate.val.getNoStripHeader<string_view>()) / (1000UL * 1000UL * 1000UL));
      d_lookupstate.rrsetpos = 0;
    }
    else {
      key = d_lookupstate.key.getNoStripHeader<string_view>();
    }
    try {
      const auto& lrr = d_lookupstate.rrset.at(d_lookupstate.rrsetpos);
      bool validRecord = d_lookupstate.includedisabled || !lrr.disabled;

      if (validRecord) {
        basename = compoundOrdername::getQName(key);
        if (!d_lookupstate.submatch.empty()) {
          validRecord = basename.isPartOf(d_lookupstate.submatch);
        }
      }

      if (!validRecord) {
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

bool LMDBBackend::get(DNSZoneRecord& zr) // NOLINT(readability-identifier-length)
{
  DNSName basename;
  std::string_view key;

  if (!getInternal(basename, key)) {
    return false;
  }
  const auto& lrr = d_lookupstate.rrset.at(d_lookupstate.rrsetpos);
  try {
    zr.dr.d_name = basename + d_lookupstate.domain.operator const DNSName&();
    zr.domain_id = compoundOrdername::getDomainID(key);
    zr.dr.d_type = compoundOrdername::getQType(key).getCode();
    zr.dr.d_ttl = lrr.ttl;
    zr.dr.setContent(deserializeContentZR(zr.dr.d_type, zr.dr.d_name, lrr.content));
    zr.auth = lrr.auth;
    zr.disabled = lrr.disabled;
  }
  catch (const std::exception& e) {
    throw PDNSException(e.what());
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
  rr.last_modified = d_lookupstate.rrsettime;

  return true;
}

void LMDBBackend::lookupEnd()
{
  d_lookupstate.reset();
  d_rotxn.reset();
}

bool LMDBBackend::getSerial(DomainInfo& di)
{
  auto txn = getRecordsROTransaction(di.id);
  compoundOrdername co;
  MDBOutVal val;
  if (!txn->txn->get(txn->db->dbi, co(di.id, g_rootdnsname, QType::SOA), val)) {
    LMDBResourceRecord lrr;
    deserializeFromBuffer(val.get<string_view>(), lrr);
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

bool LMDBBackend::getDomainInfo(const ZoneName& domain, DomainInfo& info, bool getserial)
{
  // If caller asks about a zone with variant, but views are not enabled,
  // punt.
  if (domain.hasVariant() && !d_views) {
    return false;
  }

  if (!findDomain(domain, info)) {
    return false;
  }
  info.backend = this;
  consolidateDomainInfo(info);

  if (getserial) {
    getSerial(info);
  }

  return true;
}

bool LMDBBackend::genChangeDomain(const ZoneName& domain, const std::function<void(DomainInfo&)>& func)
{
  DomainInfo info;
  if (!findDomain(domain, info)) {
    return false;
  }
  consolidateDomainInfo(info);
  func(info);
  writeDomainInfo(info);
  return true;
}

// NOLINTNEXTLINE(readability-identifier-length)
bool LMDBBackend::genChangeDomain(domainid_t id, const std::function<void(DomainInfo&)>& func)
{
  DomainInfo info;
  if (!findDomain(id, info)) {
    return false;
  }
  consolidateDomainInfo(info);
  func(info);
  writeDomainInfo(info);
  return true;
}

bool LMDBBackend::setKind(const ZoneName& domain, const DomainInfo::DomainKind kind)
{
  return genChangeDomain(domain, [kind](DomainInfo& di) {
    di.kind = kind;
  });
}

bool LMDBBackend::setAccount(const ZoneName& domain, const std::string& account)
{
  return genChangeDomain(domain, [account](DomainInfo& di) {
    di.account = account;
  });
}

bool LMDBBackend::setPrimaries(const ZoneName& domain, const vector<ComboAddress>& primaries)
{
  return genChangeDomain(domain, [&primaries](DomainInfo& di) {
    di.primaries = primaries;
  });
}

bool LMDBBackend::createDomain(const ZoneName& domain, const DomainInfo::DomainKind kind, const vector<ComboAddress>& primaries, const string& account)
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

    txn.put(info, 0, d_random_ids, domain.hash());
    txn.commit();
  }

  return true;
}

void LMDBBackend::getAllDomainsFiltered(vector<DomainInfo>* domains, const std::function<bool(DomainInfo&)>& allow)
{
  auto txn = d_tdomains->getROTransaction();
  if (d_handle_dups) {
    map<ZoneName, DomainInfo> zonemap;
    set<ZoneName> dups;

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
  getAllDomainsFiltered(domains, [this, include_disabled](DomainInfo& di) {
    if (!getSerial(di) && !include_disabled) {
      return false;
    }

    // Skip domains with variants if views are disabled.
    if (di.zone.hasVariant() && !d_views) {
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
      deserializeFromBuffer(val.get<string_view>(), lrr);
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

void LMDBBackend::setStale(domainid_t domain_id)
{
  setLastCheckTime(domain_id, 0);
}

void LMDBBackend::setFresh(domainid_t domain_id)
{
  setLastCheckTime(domain_id, time(nullptr));
}

void LMDBBackend::setLastCheckTime(domainid_t domain_id, time_t last_check)
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
    if (!container->get(info.id, tdi)) {
      // No data yet, initialize from DomainInfo
      tdi.notified_serial = info.notified_serial;
    }
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
      catalogs.insert(di.zone.operator const DNSName&());
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

void LMDBBackend::setNotified(domainid_t domain_id, uint32_t serial)
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
    if (!container->get(info.id, tdi)) {
      // No data yet, initialize from DomainInfo
      tdi.last_check = info.last_check;
    }
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

bool LMDBBackend::getCatalogMembers(const ZoneName& catalog, vector<CatalogInfo>& members, CatalogInfo::CatalogType type)
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

bool LMDBBackend::setOptions(const ZoneName& domain, const std::string& options)
{
  return genChangeDomain(domain, [options](DomainInfo& di) {
    di.options = options;
  });
}

bool LMDBBackend::setCatalog(const ZoneName& domain, const ZoneName& catalog)
{
  return genChangeDomain(domain, [catalog](DomainInfo& di) {
    di.catalog = catalog;
  });
}

bool LMDBBackend::getAllDomainMetadata(const ZoneName& name, std::map<std::string, std::vector<std::string>>& meta)
{
  meta.clear();
  auto txn = d_tmeta->getROTransaction();
  LmdbIdVec ids;
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

bool LMDBBackend::setDomainMetadata(const ZoneName& name, const std::string& kind, const std::vector<std::string>& meta)
{
  auto txn = d_tmeta->getRWTransaction();

  LmdbIdVec ids;
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
    txn.put(dm, 0, d_random_ids, burtleCI(kind, name.hash()));
  }
  txn.commit();
  return true;
}

bool LMDBBackend::getDomainKeys(const ZoneName& name, std::vector<KeyData>& keys)
{
  auto txn = d_tkdb->getROTransaction();
  LmdbIdVec ids;
  txn.get_multi<0>(name, ids);

  KeyDataDB key;

  for (auto id : ids) {
    if (txn.get(id, key)) {
      KeyData kd{key.content, id, key.flags, key.active, key.published};
      keys.emplace_back(std::move(kd));
    }
  }

  return true;
}

bool LMDBBackend::removeDomainKey(const ZoneName& name, unsigned int keyId)
{
  auto txn = d_tkdb->getRWTransaction();
  KeyDataDB kdb;
  if (txn.get(keyId, kdb)) {
    if (kdb.domain == name) {
      txn.del(keyId);
      txn.commit();
      return true;
    }
  }
  // cout << "??? wanted to remove domain key for domain "<<name<<" with id "<<keyId<<", could not find it"<<endl;
  return true;
}

bool LMDBBackend::addDomainKey(const ZoneName& name, const KeyData& key, int64_t& keyId)
{
  auto txn = d_tkdb->getRWTransaction();
  KeyDataDB kdb{name, key.content, key.flags, key.active, key.published};

  // all this just to get the tag - while most of our callers (except b2b-migrate) already have a dpk
  DNSKEYRecordContent dkrc;
  auto keyEngine = shared_ptr<DNSCryptoKeyEngine>(DNSCryptoKeyEngine::makeFromISCString(dkrc, key.content));
  DNSSECPrivateKey dpk;
  dpk.setKey(keyEngine, key.flags);
  auto tag = dpk.getDNSKEY().getTag();

  keyId = txn.put(kdb, 0, d_random_ids, name.hash(tag));
  txn.commit();

  return true;
}

bool LMDBBackend::activateDomainKey(const ZoneName& name, unsigned int keyId)
{
  auto txn = d_tkdb->getRWTransaction();
  KeyDataDB kdb;
  if (txn.get(keyId, kdb)) {
    if (kdb.domain == name) {
      txn.modify(keyId, [](KeyDataDB& kdbarg) {
        kdbarg.active = true;
      });
      txn.commit();
      return true;
    }
  }

  // cout << "??? wanted to activate domain key for domain "<<name<<" with id "<<keyId<<", could not find it"<<endl;
  return true;
}

bool LMDBBackend::deactivateDomainKey(const ZoneName& name, unsigned int keyId)
{
  auto txn = d_tkdb->getRWTransaction();
  KeyDataDB kdb;
  if (txn.get(keyId, kdb)) {
    if (kdb.domain == name) {
      txn.modify(keyId, [](KeyDataDB& kdbarg) {
        kdbarg.active = false;
      });
      txn.commit();
      return true;
    }
  }
  // cout << "??? wanted to deactivate domain key for domain "<<name<<" with id "<<keyId<<", could not find it"<<endl;
  return true;
}

bool LMDBBackend::publishDomainKey(const ZoneName& name, unsigned int keyId)
{
  auto txn = d_tkdb->getRWTransaction();
  KeyDataDB kdb;
  if (txn.get(keyId, kdb)) {
    if (kdb.domain == name) {
      txn.modify(keyId, [](KeyDataDB& kdbarg) {
        kdbarg.published = true;
      });
      txn.commit();
      return true;
    }
  }

  // cout << "??? wanted to hide domain key for domain "<<name<<" with id "<<keyId<<", could not find it"<<endl;
  return true;
}

bool LMDBBackend::unpublishDomainKey(const ZoneName& name, unsigned int keyId)
{
  auto txn = d_tkdb->getRWTransaction();
  KeyDataDB kdb;
  if (txn.get(keyId, kdb)) {
    if (kdb.domain == name) {
      txn.modify(keyId, [](KeyDataDB& kdbarg) {
        kdbarg.published = false;
      });
      txn.commit();
      return true;
    }
  }
  // cout << "??? wanted to unhide domain key for domain "<<name<<" with id "<<keyId<<", could not find it"<<endl;
  return true;
}

// Return true if the key points to an NSEC3 back chain record (ttl == 0).
bool LMDBBackend::isNSEC3BackRecord(const MDBOutVal& key, const MDBOutVal& val)
{
  if (compoundOrdername::getQType(key.getNoStripHeader<StringView>()) == QType::NSEC3) {
    if (peekAtTtl(val.get<StringView>()) == 0) {
      return true;
    }
  }
  return false;
}

// Search for the next NSEC3 back record and return its qname as `after'.
// Returns true if found, false if not (either end of database records, or
// different domain).
// NOLINTNEXTLINE(readability-identifier-length)
bool LMDBBackend::getAfterForward(MDBROCursor& cursor, MDBOutVal& key, MDBOutVal& val, domainid_t id, DNSName& after)
{
  while (!isNSEC3BackRecord(key, val)) {
    if (cursor.next(key, val) != 0 || compoundOrdername::getDomainID(key.getNoStripHeader<StringView>()) != id) {
      // cout<<"hit end of zone or database when we shouldn't"<<endl;
      return false;
    }
  }
  after = compoundOrdername::getQName(key.getNoStripHeader<StringView>());
  // cout<<"returning: before="<<before<<", after="<<after<<", unhashed: "<<unhashed<<endl;
  return true;
}

// Reset the cursor position and fall through getAfterForward.
// NOLINTNEXTLINE(readability-identifier-length)
bool LMDBBackend::getAfterForwardFromStart(MDBROCursor& cursor, MDBOutVal& key, MDBOutVal& val, domainid_t id, DNSName& after)
{
  compoundOrdername co; // NOLINT(readability-identifier-length)

  if (cursor.lower_bound(co(id), key, val) != 0) {
    // cout<<"hit end of zone find when we shouldn't"<<endl;
    return false;
  }
  return getAfterForward(cursor, key, val, id, after);
}

// NOLINTNEXTLINE(readability-identifier-length)
bool LMDBBackend::getBeforeAndAfterNamesAbsolute(domainid_t id, const DNSName& qname, DNSName& unhashed, DNSName& before, DNSName& after)
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

  string matchkey = co(id, qname, QType::NSEC3);
  if (cursor.lower_bound(matchkey, key, val)) {
    // this is beyond the end of the database
    // cout << "Beyond end of database!" << endl;
    cursor.last(key, val);

    for (;;) {
      if (co.getDomainID(key.getNoStripHeader<StringView>()) != id) {
        // cout<<"Last record also not part of this zone!"<<endl;
        //  this implies something is wrong in the database, nothing we can do
        return false;
      }

      if (isNSEC3BackRecord(key, val)) {
        break; // the kind of NSEC3 we need
      }
      if (cursor.prev(key, val)) {
        // hit beginning of database, again means something is wrong with it
        return false;
      }
    }
    before = co.getQName(key.getNoStripHeader<StringView>());
    {
      LMDBResourceRecord lrr;
      deserializeFromBuffer(val.get<StringView>(), lrr);
      unhashed = DNSName(lrr.content.c_str(), lrr.content.size(), 0, false) + info.zone.operator const DNSName&();
    }
    // now to find after .. at the beginning of the zone
    return getAfterForwardFromStart(cursor, key, val, id, after);
  }

  // cout<<"Ended up at "<<co.getQName(key.get<StringView>()) <<endl;

  before = co.getQName(key.getNoStripHeader<StringView>());
  if (before == qname) {
    // cout << "Ended up on exact right node" << endl;
    // unhashed should be correct now, maybe check?
    if (cursor.next(key, val)) {
      // xxx should find first hash now

      return getAfterForwardFromStart(cursor, key, val, id, after);
    }
  }
  else {
    // cout <<"Going backwards to find 'before'"<<endl;
    int count = 0;
    for (;;) {
      if (compoundOrdername::getQName(key.getNoStripHeader<StringView>()).canonCompare(qname)) {
        if (isNSEC3BackRecord(key, val)) {
          break;
        }
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
            // cout<<"Last record also not part of this zone!"<<endl;
            //  this implies something is wrong in the database, nothing we can do
            return false;
          }

          if (isNSEC3BackRecord(key, val)) {
            break;
          }
          if (cursor.prev(key, val)) {
            // hit beginning of database, again means something is wrong with it
            return false;
          }
        }
        before = co.getQName(key.getNoStripHeader<StringView>());
        {
          LMDBResourceRecord lrr;
          deserializeFromBuffer(val.get<StringView>(), lrr);
          unhashed = DNSName(lrr.content.c_str(), lrr.content.size(), 0, false) + info.zone.operator const DNSName&();
        }
        // cout <<"Should still find 'after'!"<<endl;
        // for 'after', we need to find the first hash of this zone

        return getAfterForwardFromStart(cursor, key, val, id, after);
      }
      ++count;
    }
    before = co.getQName(key.getNoStripHeader<StringView>());
    {
      LMDBResourceRecord lrr;
      deserializeFromBuffer(val.get<StringView>(), lrr);
      unhashed = DNSName(lrr.content.c_str(), lrr.content.size(), 0, false) + info.zone.operator const DNSName&();
    }
    // cout<<"Went backwards, found "<<before<<endl;
    // return us to starting point
    while (count-- != 0) {
      cursor.next(key, val);
    }
  }
  //  cout<<"Now going forward"<<endl;
  if (getAfterForward(cursor, key, val, id, after)) {
    return true;
  }
  // cout <<"Hit end of database or zone, finding first hash then in zone "<<id<<endl;
  // Reset cursor position and retry
  return getAfterForwardFromStart(cursor, key, val, id, after);
}

// Return whether the given entry is an authoritative record, ignoring empty
// non terminal records.
bool LMDBBackend::isValidAuthRecord(const MDBOutVal& key, const MDBOutVal& val)
{
  QType qtype = compoundOrdername::getQType(key.getNoStripHeader<string_view>()).getCode();
  switch (qtype) {
  case QType::ENT:
    return false;
  case QType::NS:
    return true;
  default:
    return peekAtAuth(val.get<string_view>());
  }
}

bool LMDBBackend::getBeforeAndAfterNames(domainid_t domainId, const ZoneName& zonenameU, const DNSName& qname, DNSName& before, DNSName& after)
{
  ZoneName zonename = zonenameU.makeLowerCase();
  //  cout << __PRETTY_FUNCTION__<< ": "<<domainId <<", "<<zonename << ", '"<<qname<<"'"<<endl;

  compoundOrdername co;
  auto txn = getRecordsROTransaction(domainId);

  auto cursor = txn->txn->getCursor(txn->db->dbi);
  MDBOutVal key, val;

  DNSName qname2 = qname.makeRelative(zonename);
  string matchkey = co(domainId, qname2);
  // cout<<"Lower_bound for "<<qname2<<endl;
  if (cursor.lower_bound(matchkey, key, val)) {
    // cout << "Hit end of database, bummer"<<endl;
    cursor.last(key, val);
    if (compoundOrdername::getDomainID(key.getNoStripHeader<string_view>()) == domainId) {
      before = compoundOrdername::getQName(key.getNoStripHeader<string_view>()) + zonename.operator const DNSName&();
      after = zonename.operator const DNSName&();
    }
    // else
    // cout << "We were at end of database, but this zone is not there?!"<<endl;
    return true;
  }
  // cout<<"Cursor is at "<<co.getQName(key.get<string_view>()) <<", in zone id "<<compoundOrdername::getDomainID(key.get<string_view>())<< endl;

  if (compoundOrdername::getQType(key.getNoStripHeader<string_view>()).getCode() != 0 && compoundOrdername::getDomainID(key.getNoStripHeader<string_view>()) == domainId && compoundOrdername::getQName(key.getNoStripHeader<string_view>()) == qname2) { // don't match ENTs
    // cout << "Had an exact match!"<<endl;
    before = qname; // i.e. qname2 + zonename.operator const DNSName&();
    int rc;
    for (;;) {
      rc = cursor.next(key, val);
      if (rc)
        break;

      if (compoundOrdername::getDomainID(key.getNoStripHeader<string_view>()) == domainId && key.getNoStripHeader<StringView>().rfind(matchkey, 0) == 0) {
        continue;
      }
      if (isValidAuthRecord(key, val)) {
        break;
      }
    }
    if (rc != 0 || compoundOrdername::getDomainID(key.getNoStripHeader<string_view>()) != domainId) {
      // cout << "We hit the end of the zone or database. 'after' is apex" << endl;
      after = zonename.operator const DNSName&();
      return false;
    }
    after = compoundOrdername::getQName(key.getNoStripHeader<string_view>()) + zonename.operator const DNSName&();
    return true;
  }

  if (compoundOrdername::getDomainID(key.getNoStripHeader<string_view>()) != domainId) {
    // cout << "Ended up in next zone, 'after' is zonename" <<endl;
    after = zonename.operator const DNSName&();
    // cout << "Now hunting for previous" << endl;
    int rc;
    for (;;) {
      rc = cursor.prev(key, val);
      if (rc) {
        // cout<<"Reversed into zone, but got not found from lmdb" <<endl;
        return false;
      }

      if (compoundOrdername::getDomainID(key.getNoStripHeader<string_view>()) != domainId) {
        // cout<<"Reversed into zone, but found wrong zone id " << compoundOrdername::getDomainID(key.getNoStripHeader<string_view>()) << " != "<<domainId<<endl;
        // "this can't happen"
        return false;
      }
      if (isValidAuthRecord(key, val)) {
        break;
      }
    }

    before = compoundOrdername::getQName(key.getNoStripHeader<string_view>()) + zonename.operator const DNSName&();
    // cout<<"Found: "<< before<<endl;
    return true;
  }

  // cout <<"We ended up after "<<qname<<", on "<<co.getQName(key.getNoStripHeader<string_view>())<<endl;

  int skips = 0;
  for (;;) {
    if (isValidAuthRecord(key, val)) {
      after = compoundOrdername::getQName(key.getNoStripHeader<string_view>()) + zonename.operator const DNSName&();
      // Note: change isValidAuthRecord to also return the LMDBResourceRecord if
      // uncommenting these debug messages...
      // cout <<"Found auth ("<<lrr.auth<<") or an NS record "<<after<<", type: "<<co.getQType(key.getNoStripHeader<string_view>()).toString()<<", ttl = "<<lrr.ttl<<endl;
      // cout << makeHexDump(val.get<string>()) << endl;
      break;
    }
    // cout <<"  oops, " << co.getQName(key.getNoStripHeader<string_view>()) << " was not auth "<<lrr.auth<< " type=" << lrr.qtype.toString()<<" or NS, so need to skip ahead a bit more" << endl;
    int rc = cursor.next(key, val);
    if (!rc)
      ++skips;
    if (rc != 0 || compoundOrdername::getDomainID(key.getNoStripHeader<string_view>()) != domainId) {
      // cout << "  oops, hit end of database or zone. This means after is apex" <<endl;
      after = zonename.operator const DNSName&();
      break;
    }
  }
  // go back to where we were
  while (skips--)
    cursor.prev(key, val);

  for (;;) {
    int rc = cursor.prev(key, val);
    if (rc != 0 || compoundOrdername::getDomainID(key.getNoStripHeader<string_view>()) != domainId) {
      // XX I don't think this case can happen
      // cout << "We hit the beginning of the zone or database.. now what" << endl;
      return false;
    }
    before = compoundOrdername::getQName(key.getNoStripHeader<string_view>()) + zonename.operator const DNSName&();
    // cout<<"And before to "<<before<<", auth = "<<rr.auth<<endl;
    if (isValidAuthRecord(key, val)) {
      break;
    }
    // cout << "Oops, that was wrong, go back one more"<<endl;
  }

  return true;
}

bool LMDBBackend::updateDNSSECOrderNameAndAuth(domainid_t domain_id, const DNSName& qname, const DNSName& ordername, bool auth, const uint16_t qtype, bool isNsec3)
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

  bool hadOrderName{false};
  bool hasOrderName = !ordername.empty() && isNsec3;
  bool keepNSEC3 = hasOrderName;

  do {
    if (compoundOrdername::getQType(key.getNoStripHeader<StringView>()) == QType::NSEC3) {
      hadOrderName = true;
      continue;
    }

    vector<LMDBResourceRecord> lrrs;
    deserializeFromBuffer(val.get<StringView>(), lrrs);
    bool changed = false;
    vector<LMDBResourceRecord> newRRs;
    newRRs.reserve(lrrs.size());
    for (auto& lrr : lrrs) {
      hadOrderName |= lrr.hasOrderName;
      lrr.qtype = compoundOrdername::getQType(key.getNoStripHeader<StringView>());
      bool isDifferentQType = qtype != QType::ANY && QType(qtype) != lrr.qtype;
      // If there is at least one entry for that qname, with a different qtype
      // than the one we are working for, known to be associated to an NSEC3
      // record, then we should NOT delete it.
      if (!keepNSEC3) {
        keepNSEC3 = lrr.hasOrderName && isDifferentQType;
      }

      if (!isDifferentQType && (lrr.hasOrderName != hasOrderName || lrr.auth != auth)) {
        lrr.auth = auth;
        lrr.hasOrderName = hasOrderName;
        changed = true;
      }
      newRRs.push_back(std::move(lrr));
    }
    if (changed) {
      std::string ser = MDBRWTransactionImpl::stringWithEmptyHeader();
      serializeToBuffer(ser, newRRs);
      cursor.put_header_in_place(key, ser);
    }
  } while (cursor.next(key, val) == 0);

  if (!keepNSEC3) {
    // NSEC3 link to be removed: need to remove an existing pair, if any
    if (hadOrderName) {
      deleteNSEC3RecordPair(txn, domain_id, rel);
    }
  }
  else if (hasOrderName) {
    // NSEC3 link to be added or updated
    writeNSEC3RecordPair(txn, domain_id, rel, ordername);
  }

  if (needCommit)
    txn->txn->commit();
  return false;
}

bool LMDBBackend::updateEmptyNonTerminals(domainid_t domain_id, set<DNSName>& insert, set<DNSName>& erase, bool remove)
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

  // if remove is set, all ENTs should be removed
  compoundOrdername order;
  if (remove) {
    string match = order(domain_id);
    // We can not simply blindly delete all ENT records the way
    // deleteDomainRecords() would do, as we also need to remove
    // NSEC3 records for these ENT, if any.
    {
      auto cursor = txn->txn->getCursor(txn->db->dbi);
      MDBOutVal key{};
      MDBOutVal val{};
      std::vector<DNSName> names;

      while (cursor.prefix(match, key, val) == 0) {
        do {
          if (compoundOrdername::getQType(key.getNoStripHeader<StringView>()) == QType::ENT) {
            // We need to remember the name of the records we're deleting, so
            // as to remove the matching NSEC3 records, if any.
            // (we can't invoke deleteNSEC3RecordPair here as doing this
            // could make our cursor invalid)
            if (peekAtHasOrderName(val.get<string_view>())) {
              DNSName qname = compoundOrdername::getQName(key.getNoStripHeader<StringView>());
              names.emplace_back(qname);
            }
            cursor.del(key);
            // Do not risk accumulating too many names. Better iterate
            // multiple times, there won't be any ENT left eventually.
            if (names.size() >= 100) {
              break;
            }
          }
        } while (cursor.next(key, val) == 0);
        for (const auto& qname : names) {
          deleteNSEC3RecordPair(txn, domain_id, qname);
        }
        names.clear();
      }
    }
  }
  else {
    for (auto name : erase) {
      // cout <<" -"<<name<<endl;
      name.makeUsRelative(info.zone);
      std::string match = order(domain_id, name, QType::ENT);
      MDBOutVal val{};
      if (txn->txn->get(txn->db->dbi, match, val) == 0) {
        bool hadOrderName = peekAtHasOrderName(val.get<string_view>());
        txn->txn->del(txn->db->dbi, match);
        if (hadOrderName) {
          deleteNSEC3RecordPair(txn, domain_id, name);
        }
      }
    }
  }
  for (const auto& name : insert) {
    LMDBResourceRecord lrr;
    lrr.qname = name.makeRelative(info.zone);
    lrr.ttl = 0;
    lrr.auth = true;
    std::string ser = MDBRWTransactionImpl::stringWithEmptyHeader();
    serializeToBuffer(ser, lrr);
    txn->txn->put_header_in_place(txn->db->dbi, order(domain_id, lrr.qname, QType::ENT), ser);
    // cout <<" +"<<name<<endl;
  }
  if (needCommit) {
    txn->txn->commit();
  }
  return false;
}

/* TSIG */
bool LMDBBackend::getTSIGKey(const DNSName& name, DNSName& algorithm, string& content)
{
  auto txn = d_ttsig->getROTransaction();
  LmdbIdVec ids;
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

  LmdbIdVec ids;
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

  txn.put(tk, 0, d_random_ids, name.hash());
  txn.commit();

  return true;
}
bool LMDBBackend::deleteTSIGKey(const DNSName& name)
{
  auto txn = d_ttsig->getRWTransaction();

  LmdbIdVec ids;
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
  // In a perfect world, we would simply iterate over txn and add every
  // item to the returned vector:
  //   for (auto iter = txn.begin(); iter != txn.end(); ++iter) {
  //     keys.push_back(*iter);
  //   }
  // But databases converted from older (< 5) schemas _may_ have multiple
  // entries for the same TSIG key name and algorithm, something which is not
  // allowed in the v5 database schema. These extra entries will not be found
  // by get_multi<> during regular operations, and would only appear in the
  // results of this method.
  // In order to prevent this, we first only gather the list of key names, and
  // in a second step, query for them using a similar logic as getTSIGKey().
  // Unfortunately, there does not seem to be a way to know if the database had
  // been created using the v5 schema (not converted), in which case we could
  // use the above, simpler logic.
  std::unordered_set<DNSName> keynames;
  for (const auto& iter : txn) {
    keynames.insert(iter.name);
  }
  for (const auto& iter : keynames) {
    LmdbIdVec ids;
    txn.get_multi<0>(iter, ids);
    for (auto key_id : ids) {
      TSIGKey key;
      if (txn.get(key_id, key)) {
        keys.push_back(key);
      }
    }
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

          LmdbIdVec ids;
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

      domainid_t id = 0; // NOLINT(readability-identifier-length)

      try {
        pdns::checked_stoi_into(id, argv[3]);
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

  if (cmd == "list") {
    return directBackendCmd_list(argv);
  }

  return "unknown lmdbbackend command\n";
}

string LMDBBackend::directBackendCmd_list(std::vector<string>& argv)
{
  ostringstream ret;

  if (argv.size() < 2) {
    ret << "need a domain name" << endl;
    return ret.str();
  }
  ZoneName zone(argv[1]);

  DomainInfo info;
  if (!getDomainInfo(zone, info, false)) {
    ret << "zone " << zone << " not found" << endl;
    return ret.str();
  }
  list(zone, info.id, true);
  {
    DNSName basename;
    std::string_view key;
    while (getInternal(basename, key)) {
      const auto& lrr = d_lookupstate.rrset.at(d_lookupstate.rrsetpos);
      DNSName qname = basename + d_lookupstate.domain.operator const DNSName&();
      QType qtype = compoundOrdername::getQType(key);
      DNSRecord record;
      record.setContent(deserializeContentZR(qtype, qname, lrr.content));
      std::string content = record.getContent()->getZoneRepresentation(true);
      // Mimic the `prio' field in SQL
      int prio{0};
      if (qtype == QType::MX || qtype == QType::SRV) {
        if (auto pos = content.find_first_not_of("0123456789"); pos != std::string::npos) {
          pdns::checked_stoi_into(prio, content.substr(0, pos));
          content.erase(0, pos);
          boost::trim_left(content);
        }
      }
      ret << qname << "\t" << qtype.toString() << "\t" << prio << "\t" << content << "\t" << lrr.ttl;
      if (lrr.hasOrderName) {
        ret << "\t'";
        // The get() logic skips the NSEC3 records containing the information
        // we need, and there is no way to nest lookups. But the NSEC3
        // record has a unique key we can compute, so we can fetch it
        // without disturbing the current get() cursor.
        compoundOrdername order;
        MDBOutVal val{};
        if (d_rotxn->txn->get(d_rotxn->db->dbi, order(info.id, basename, QType::NSEC3), val) == 0) {
          LMDBResourceRecord nsec3rr;
          deserializeFromBuffer(val.get<string_view>(), nsec3rr);
          DNSName ordername(nsec3rr.content.c_str(), nsec3rr.content.size(), 0, false);
          ret << ordername;
        }
        ret << "'\t";
        ret << static_cast<int>(lrr.auth);
      }
      ret << std::endl;
    }
  }
  return ret.str();
}

bool LMDBBackend::hasCreatedLocalFiles() const
{
  // Since the lmdb file creation counter is global, if multiple LMDB backends
  // are used, they may end up all reporting having created files even if
  // not all of them did.
  // But since this information is for the sake of pdnsutil, this is not
  // really a problem.
  return MDBDbi::d_creationCount != 0;
}

// Hook for rectifyZone operation.
// Before the operation starts, we forcibly remove all NSEC3 records from the
// domain, since logic flaws in older versions may have left us with dangling
// records. The appropriate records will be regenerated with
// updateDNSSECOrderNameAndAuth() calls anyway.
void LMDBBackend::rectifyZoneHook(domainid_t domain_id, bool before) const
{
  if (!before) {
    return;
  }

  if (!d_rwtxn) {
    throw DBException("rectifyZoneHook invoked outside of a transaction");
  }

  compoundOrdername order;
  LMDBBackend::deleteDomainRecords(*d_rwtxn, order(domain_id), QType::NSEC3);
}

void LMDBBackend::flush()
{
  if (d_write_notification_update) {
    return; // no data needs to be synchronized
  }

  // We flush in chunks of 10 domains, in order not to keep the serial number
  // cache locked for too long.
  while (true) {
    unsigned int done = 0;
    auto container = s_transient_domain_info.write_lock();
    for (; done < 10; ++done) {
      domainid_t domid{};
      TransientDomainInfo tdi;
      if (!container->pop(domid, tdi)) {
        break;
      }
      DomainInfo info;
      if (findDomain(domid, info)) {
        info.notified_serial = tdi.notified_serial;
        info.last_check = tdi.last_check;
        auto txn = d_tdomains->getRWTransaction();
        txn.put(info, info.id);
        txn.commit();
      }
      else {
        // Domain has been removed. This should not happen because deletion
        // is supposed to take care of removing the entry here too.
        // Is it worth logging something here?
      }
    }
    if (done == 0) {
      break; // no more work to do!
    }
  }
}

int LMDBBackend::getStorageLayoutVersion()
{
  return static_cast<int>(d_currentschema);
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
    declare(suffix, "map-size", "main LMDB map size in megabytes", (sizeof(void*) == 4) ? "100" : "16000");
    declare(suffix, "shards-map-size", "shard LMDB map size in megabytes, zero to use the same size as main", "0");
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
