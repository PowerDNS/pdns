#include "config.h"
#include "lmdb-safe.hh"

#include <fcntl.h>
#include <mutex>
#include <memory>
#include <sys/stat.h>
#include <cstring>
#include <map>

#ifndef DNSDIST
#include "../../pdns/gettime.hh"
#endif

using std::string;
using std::runtime_error;
using std::tuple;
using std::weak_ptr;

static string MDBError(int rc)
{
  return mdb_strerror(rc);
}

#ifndef DNSDIST

namespace LMDBLS {
  // this also returns a pointer to the string's data. Do not hold on to it too long!
  const LSheader* LSassertFixedHeaderSize(std::string_view val) {
    // cerr<<"val.size()="<<val.size()<<endl;
    if (val.size() < LS_MIN_HEADER_SIZE) {
      throw std::runtime_error("LSheader too short");
    }

    return reinterpret_cast<const LSheader*>(val.data());
  }

  size_t LScheckHeaderAndGetSize(std::string_view val, size_t datasize) {
    const LSheader* lsh = LSassertFixedHeaderSize(val);

    if (lsh->d_version != 0) {
      throw std::runtime_error("LSheader has wrong version (not zero)");
    }

    size_t headersize = LS_MIN_HEADER_SIZE;

    unsigned char* tmp = (unsigned char*)val.data();
    uint16_t numextra = (tmp[LS_NUMEXTRA_OFFSET] << 8) + tmp[LS_NUMEXTRA_OFFSET+1];

    headersize += numextra * LS_BLOCK_SIZE;

    if (val.size() < headersize) {
      throw std::runtime_error("LSheader too short for promised extra data");
    }

    if (datasize && val.size() < (headersize+datasize)) {
      throw std::runtime_error("Trailing data after LSheader has wrong size");
    }

    return headersize;
  }

  size_t LScheckHeaderAndGetSize(const MDBOutVal *val, size_t datasize) {
    return LScheckHeaderAndGetSize(val->getNoStripHeader<string_view>(), datasize);
  }

  bool LSisDeleted(std::string_view val) {
    const LSheader* lsh = LSassertFixedHeaderSize(val);

    return (lsh->d_flags & LS_FLAG_DELETED) != 0;
  }

  uint64_t LSgetTimestamp(std::string_view val) {
    const LSheader* lsh = LSassertFixedHeaderSize(val);

    return lsh->getTimestamp();
  }
  bool s_flag_deleted{false};
}

#endif /* #ifndef DNSDIST */

std::atomic<unsigned int> MDBDbi::d_creationCount{0};

MDBDbi::MDBDbi(MDB_env* /* env */, MDB_txn* txn, const string_view dbname, int flags) : d_dbi(-1)
{
  // A transaction that uses this function must finish (either commit or abort) before any other transaction in the process may use this function.

  int ret = MDBDbi::mdb_dbi_open(txn, dbname.empty() ? nullptr : dbname.data(), flags, &d_dbi);
  if (ret != 0) {
    throw std::runtime_error("Unable to open named database: " + MDBError(ret));
  }

  // Database names are keys in the unnamed database, and may be read but not written.
}

// This is a wrapper around the real mdb_dbi_open(), in order to track creation
// of new files.
int MDBDbi::mdb_dbi_open(MDB_txn* txn, const char* name, unsigned int flags, MDB_dbi* dbi)
{
  if ((flags & MDB_CREATE) != 0) {
    flags &= ~MDB_CREATE;
    int retval = ::mdb_dbi_open(txn, name, flags, dbi);
    if (retval == MDB_NOTFOUND) {
      flags |= MDB_CREATE;
      retval = ::mdb_dbi_open(txn, name, flags, dbi);
      if (retval == 0) {
        d_creationCount++;
      }
    }
    return retval;
  }
  return ::mdb_dbi_open(txn, name, flags, dbi);
}

MDBEnv::MDBEnv(const char* fname, int flags, int mode, uint64_t mapsizeMB)
{
  mdb_env_create(&d_env);
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

  if ((flags & MDB_RDONLY) == 0) {
    // Check for stale readers to prevent unbridled database growth.
    // Only do this when in RW mode since it affects the file.
    mdb_reader_check(d_env, nullptr);
  }
}

void MDBEnv::incROTX()
{
  auto threadId = std::this_thread::get_id();
  {
    std::shared_lock<std::shared_mutex> lock(d_countmutex);
    if (auto transactionsIt = d_ROtransactionsOut.find(threadId); transactionsIt != d_ROtransactionsOut.end()) {
      ++transactionsIt->second;
      return;
    }
  }

  {
    std::unique_lock<std::shared_mutex> lock(d_countmutex);
    auto [transactionsIt, inserted] = d_ROtransactionsOut.emplace(threadId, 1);
    if (!inserted) {
      ++transactionsIt->second;
    }
  }
}

void MDBEnv::decROTX()
{
  auto threadId = std::this_thread::get_id();
  {
    std::shared_lock<std::shared_mutex> lock(d_countmutex);
    d_ROtransactionsOut.at(threadId)--;
  }
}

void MDBEnv::incRWTX()
{
  auto threadId = std::this_thread::get_id();
  {
    std::shared_lock<std::shared_mutex> lock(d_countmutex);
    if (auto transactionsIt = d_RWtransactionsOut.find(threadId); transactionsIt != d_RWtransactionsOut.end()) {
      ++transactionsIt->second;
      return;
    }
  }

  {
    std::unique_lock<std::shared_mutex> lock(d_countmutex);
    auto [transactionsIt, inserted] = d_RWtransactionsOut.emplace(threadId, 1);
    if (!inserted) {
      ++transactionsIt->second;
    }
  }
}

void MDBEnv::decRWTX()
{
  auto threadId = std::this_thread::get_id();
  {
    std::shared_lock<std::shared_mutex> lock(d_countmutex);
    d_RWtransactionsOut.at(threadId)--;
  }
}

int MDBEnv::getRWTX()
{
  auto threadId = std::this_thread::get_id();
  {
    std::shared_lock<std::shared_mutex> lock(d_countmutex);
    if (auto transactionsIt = d_RWtransactionsOut.find(threadId); transactionsIt != d_RWtransactionsOut.end()) {
      return transactionsIt->second.load();
    }
  }
  return 0;
}

int MDBEnv::getROTX()
{
  auto threadId = std::this_thread::get_id();
  {
    std::shared_lock<std::shared_mutex> lock(d_countmutex);
    if (auto transactionsIt = d_RWtransactionsOut.find(threadId); transactionsIt != d_RWtransactionsOut.end()) {
      return transactionsIt->second.load();
    }
  }
  return 0;
}


std::shared_ptr<MDBEnv> getMDBEnv(const char* fname, int flags, int mode, uint64_t mapsizeMB)
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
      auto fresh = std::make_shared<MDBEnv>(fname, flags, mode, mapsizeMB);
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

  auto fresh = std::make_shared<MDBEnv>(fname, flags, mode, mapsizeMB);
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
    MDBDbi ret = rwt->openDB(dbname, flags);
    rwt->commit();
    return ret;
  }

  MDBDbi ret;
  {
    auto rwt = getROTransaction();
    ret = rwt->openDB(dbname, flags);
  }
  return ret;
}

MDBRWTransactionImpl::MDBRWTransactionImpl(MDBEnv *parent, MDB_txn *txn):
  MDBROTransactionImpl(parent, txn)

{

}

MDB_txn *MDBRWTransactionImpl::openRWTransaction(MDBEnv *env, MDB_txn *parent, int flags)
{
  MDB_txn *result;
  if(env->getRWTX() != 0) {
    throw std::runtime_error("Duplicate RW transaction");
  }

  if(int rc=mdb_txn_begin(env->d_env, parent, flags, &result))
    throw std::runtime_error("Unable to start RW transaction: "+std::string(mdb_strerror(rc)));

  env->incRWTX();
  return result;
}

MDBRWTransactionImpl::MDBRWTransactionImpl(MDBEnv* parent, int flags):
  MDBRWTransactionImpl(parent, openRWTransaction(parent, nullptr, flags))
{
#ifndef DNSDIST
  struct timespec tp;

  gettime(&tp, true);

  d_txtime = tp.tv_sec * (1000 * 1000 * 1000) + tp.tv_nsec;
#endif
}

MDBRWTransactionImpl::~MDBRWTransactionImpl()
{
  abort();
}

void MDBRWTransactionImpl::commit()
{
  closeRORWCursors();
  if (!d_txn) {
    return;
  }

  if(int rc = mdb_txn_commit(d_txn)) {
    throw std::runtime_error("committing: " + std::string(mdb_strerror(rc)));
  }
  environment().decRWTX();
  d_txn = nullptr;
}

void MDBRWTransactionImpl::abort()
{
  closeRORWCursors();
  if (!d_txn) {
    return;
  }

  mdb_txn_abort(d_txn);
  // prevent the RO destructor from cleaning up the transaction itself
  environment().decRWTX();
  d_txn = nullptr;
}

MDBROTransactionImpl::MDBROTransactionImpl(MDBEnv *parent, MDB_txn *txn):
  d_parent(parent),
  d_cursors(),
  d_txn(txn)
{

}

MDB_txn *MDBROTransactionImpl::openROTransaction(MDBEnv *env, MDB_txn *parent, int flags)
{
  if(env->getRWTX())
    throw std::runtime_error("Duplicate RO transaction");

  /*
    A transaction and its cursors must only be used by a single thread, and a thread may only have a single transaction at a time. If MDB_NOTLS is in use, this does not apply to read-only transactions. */
  MDB_txn *result = nullptr;

  if(int rc=mdb_txn_begin(env->d_env, parent, MDB_RDONLY | flags, &result))
    throw std::runtime_error("Unable to start RO transaction: "+string(mdb_strerror(rc)));

  env->incROTX();

  return result;
}

void MDBROTransactionImpl::closeROCursors()
{
  // we need to move the vector away to ensure that the cursors don’t mess with our iteration.
  std::vector<MDBROCursor*> buf;
  std::swap(d_cursors, buf);
  for (auto &cursor: buf) {
    cursor->close();
  }
}

MDBROTransactionImpl::MDBROTransactionImpl(MDBEnv *parent, int flags):
    MDBROTransactionImpl(parent, openROTransaction(parent, nullptr, flags))
{

}

MDBROTransactionImpl::~MDBROTransactionImpl()
{
  // this is safe because C++ will not call overrides of virtual methods in destructors.
  MDBROTransactionImpl::commit();
}

void MDBROTransactionImpl::abort()
{
  closeROCursors();
  // if d_txn is non-nullptr here, either the transaction object was invalidated earlier (e.g. by moving from it), or it is an RW transaction which has already cleaned up the d_txn pointer (with an abort).
  if (d_txn) {
    d_parent->decROTX();
    mdb_txn_abort(d_txn); // this appears to work better than abort for r/o database opening
    d_txn = nullptr;
  }
}

void MDBROTransactionImpl::commit()
{
  closeROCursors();
  // if d_txn is non-nullptr here, either the transaction object was invalidated earlier (e.g. by moving from it), or it is an RW transaction which has already cleaned up the d_txn pointer (with an abort).
  if (d_txn) {
    d_parent->decROTX();
    mdb_txn_commit(d_txn); // this appears to work better than abort for r/o database opening
    d_txn = nullptr;
  }
}



void MDBRWTransactionImpl::clear(MDB_dbi dbi)
{
  if(int rc = mdb_drop(d_txn, dbi, 0)) {
    throw runtime_error("Error clearing database: " + MDBError(rc));
  }
}

MDBRWCursor MDBRWTransactionImpl::getRWCursor(const MDBDbi& dbi)
{
  MDB_cursor *cursor;
  int rc= mdb_cursor_open(d_txn, dbi, &cursor);
  if(rc) {
    throw std::runtime_error("Error creating RW cursor: "+std::string(mdb_strerror(rc)));
  }

  return MDBRWCursor(d_rw_cursors, cursor, d_txn, d_txtime);
}

MDBRWCursor MDBRWTransactionImpl::getCursor(const MDBDbi &dbi)
{
  return getRWCursor(dbi);
}

MDBRWTransaction MDBRWTransactionImpl::getRWTransaction()
{
  MDB_txn *txn;
  if (int rc = mdb_txn_begin(environment(), *this, 0, &txn)) {
    throw std::runtime_error(std::string("failed to start child transaction: ")+mdb_strerror(rc));
  }
  // we need to increase the counter here because commit/abort on the child transaction will decrease it
  environment().incRWTX();
  return MDBRWTransaction(new MDBRWTransactionImpl(&environment(), txn));
}

MDBROTransaction MDBRWTransactionImpl::getROTransaction()
{
  return getRWTransaction();
}

MDBROTransaction MDBEnv::getROTransaction()
{
  return MDBROTransaction(new MDBROTransactionImpl(this));
}
MDBRWTransaction MDBEnv::getRWTransaction()
{
  return MDBRWTransaction(new MDBRWTransactionImpl(this));
}


void MDBRWTransactionImpl::closeRWCursors()
{
  decltype(d_rw_cursors) buf;
  std::swap(d_rw_cursors, buf);
  for (auto &cursor: buf) {
    cursor->close();
  }
}

MDBROCursor MDBROTransactionImpl::getCursor(const MDBDbi& dbi)
{
  return getROCursor(dbi);
}

MDBROCursor MDBROTransactionImpl::getROCursor(const MDBDbi &dbi)
{
  MDB_cursor *cursor;
  int rc= mdb_cursor_open(d_txn, dbi, &cursor);
  if(rc) {
    throw std::runtime_error("Error creating RO cursor: "+std::string(mdb_strerror(rc)));
  }
  return MDBROCursor(d_cursors, cursor);
}
