#include "lmdb-safe.hh"
#include <fcntl.h>
#include <mutex>
#include <memory>
#include <sys/stat.h>
#include <string.h>
#include <map>

using namespace std;

static string MDBError(int rc)
{
  return mdb_strerror(rc);
}

MDBDbi::MDBDbi(MDB_env* env, MDB_txn* txn, const string_view dbname, int flags)
{
  // A transaction that uses this function must finish (either commit or abort) before any other transaction in the process may use this function.
  
  int rc = mdb_dbi_open(txn, dbname.empty() ? 0 : &dbname[0], flags, &d_dbi);
  if(rc)
    throw std::runtime_error("Unable to open named database: " + MDBError(rc));
  
  // Database names are keys in the unnamed database, and may be read but not written.
}

MDBEnv::MDBEnv(const char* fname, int flags, int mode)
{
  mdb_env_create(&d_env);
  uint64_t mapsizeMB = (sizeof(long)==4) ? 100 : 16000;
  // on 32 bit platforms, there is just no room for more
  if(mdb_env_set_mapsize(d_env, mapsizeMB * 1048576))
    throw std::runtime_error("setting map size");
    /*
Various other options may also need to be set before opening the handle, e.g. mdb_env_set_mapsize(), mdb_env_set_maxreaders(), mdb_env_set_maxdbs(),
    */

  mdb_env_set_maxdbs(d_env, 128);

  // we need MDB_NOTLS since we rely on its semantics
  if(int rc=mdb_env_open(d_env, fname, flags | MDB_NOTLS, mode)) {
    // If this function fails, mdb_env_close() must be called to discard the MDB_env handle.
    mdb_env_close(d_env);
    throw std::runtime_error("Unable to open database file "+std::string(fname)+": " + MDBError(rc));
  }
}

void MDBEnv::incROTX()
{
  std::lock_guard<std::mutex> l(d_countmutex);
  ++d_ROtransactionsOut[std::this_thread::get_id()];
}

void MDBEnv::decROTX()
{
  std::lock_guard<std::mutex> l(d_countmutex);
  --d_ROtransactionsOut[std::this_thread::get_id()];
}

void MDBEnv::incRWTX()
{
  std::lock_guard<std::mutex> l(d_countmutex);
  ++d_RWtransactionsOut[std::this_thread::get_id()];
}

void MDBEnv::decRWTX()
{
  std::lock_guard<std::mutex> l(d_countmutex);
  --d_RWtransactionsOut[std::this_thread::get_id()];
}

int MDBEnv::getRWTX()
{
  std::lock_guard<std::mutex> l(d_countmutex);
  return d_RWtransactionsOut[std::this_thread::get_id()];
}
int MDBEnv::getROTX()
{
  std::lock_guard<std::mutex> l(d_countmutex);
  return d_ROtransactionsOut[std::this_thread::get_id()];
}


std::shared_ptr<MDBEnv> getMDBEnv(const char* fname, int flags, int mode)
{
  struct Value
  {
    weak_ptr<MDBEnv> wp;
    int flags;
  };
  
  static std::map<tuple<dev_t, ino_t>, Value> s_envs;
  static std::mutex mut;
  
  struct stat statbuf;
  if(stat(fname, &statbuf)) {
    if(errno != ENOENT)
      throw std::runtime_error("Unable to stat prospective mdb database: "+string(strerror(errno)));
    else {
      std::lock_guard<std::mutex> l(mut);
      auto fresh = std::make_shared<MDBEnv>(fname, flags, mode);
      if(stat(fname, &statbuf))
        throw std::runtime_error("Unable to stat prospective mdb database: "+string(strerror(errno)));
      auto key = std::tie(statbuf.st_dev, statbuf.st_ino);
      s_envs[key] = {fresh, flags};
      return fresh;
    }
  }

  std::lock_guard<std::mutex> l(mut);
  auto key = std::tie(statbuf.st_dev, statbuf.st_ino);
  auto iter = s_envs.find(key);
  if(iter != s_envs.end()) {
    auto sp = iter->second.wp.lock();
    if(sp) {
      if(iter->second.flags != flags)
        throw std::runtime_error("Can't open mdb with differing flags");

      return sp;
    }
    else {
      s_envs.erase(iter); // useful if make_shared fails
    }
  }

  auto fresh = std::make_shared<MDBEnv>(fname, flags, mode);
  s_envs[key] = {fresh, flags};
  
  return fresh;
}


MDBDbi MDBEnv::openDB(const string_view dbname, int flags)
{
  unsigned int envflags;
  mdb_env_get_flags(d_env, &envflags);
  /*
    This function must not be called from multiple concurrent transactions in the same process. A transaction that uses this function must finish (either commit or abort) before any other transaction in the process may use this function.
  */
  std::lock_guard<std::mutex> l(d_openmut);
  
  if(!(envflags & MDB_RDONLY)) {
    auto rwt = getRWTransaction();
    MDBDbi ret = rwt.openDB(dbname, flags);
    rwt.commit();
    return ret;
  }

  MDBDbi ret;
  {
    auto rwt = getROTransaction(); 
    ret = rwt.openDB(dbname, flags);
  }
  return ret;
}

MDBRWTransaction::MDBRWTransaction(MDBEnv* parent, int flags) : d_parent(parent)
{
  if(d_parent->getROTX() || d_parent->getRWTX())
    throw std::runtime_error("Duplicate RW transaction");

  for(int tries =0 ; tries < 3; ++tries) { // it might happen twice, who knows
    if(int rc=mdb_txn_begin(d_parent->d_env, 0, flags, &d_txn)) {
      if(rc == MDB_MAP_RESIZED && tries < 2) {
        // "If the mapsize is increased by another process (..) mdb_txn_begin() will return MDB_MAP_RESIZED.
        // call mdb_env_set_mapsize with a size of zero to adopt the new size."
        mdb_env_set_mapsize(d_parent->d_env, 0);
        continue;
      }
      throw std::runtime_error("Unable to start RW transaction: "+std::string(mdb_strerror(rc)));
    }
    break;
  }
  d_parent->incRWTX();
}

MDBROTransaction::MDBROTransaction(MDBEnv* parent, int flags) : d_parent(parent)
{
  if(d_parent->getRWTX())
    throw std::runtime_error("Duplicate RO transaction");
  
  /*
    A transaction and its cursors must only be used by a single thread, and a thread may only have a single transaction at a time. If MDB_NOTLS is in use, this does not apply to read-only transactions. */
  
  for(int tries =0 ; tries < 3; ++tries) { // it might happen twice, who knows
    if(int rc=mdb_txn_begin(d_parent->d_env, 0, MDB_RDONLY | flags, &d_txn)) {
      if(rc == MDB_MAP_RESIZED && tries < 2) {
        // "If the mapsize is increased by another process (..) mdb_txn_begin() will return MDB_MAP_RESIZED.
        // call mdb_env_set_mapsize with a size of zero to adopt the new size."
        mdb_env_set_mapsize(d_parent->d_env, 0);
        continue;
      }

      throw std::runtime_error("Unable to start RO transaction: "+string(mdb_strerror(rc)));
    }
    break;
  }
  d_parent->incROTX();
}



void MDBRWTransaction::clear(MDB_dbi dbi)
{
  if(int rc = mdb_drop(d_txn, dbi, 0)) {
    throw runtime_error("Error clearing database: " + MDBError(rc));
  }
}

MDBRWCursor MDBRWTransaction::getCursor(const MDBDbi& dbi)
{
  return MDBRWCursor(this, dbi);
}

MDBROTransaction MDBEnv::getROTransaction()
{
  return MDBROTransaction(this);
}
MDBRWTransaction MDBEnv::getRWTransaction()
{
  return MDBRWTransaction(this);
}


void MDBRWTransaction::closeCursors()
{
  for(auto& c : d_cursors)
    c->close();
  d_cursors.clear();
}

MDBROCursor MDBROTransaction::getCursor(const MDBDbi& dbi)
{
  return MDBROCursor(this, dbi);
}


