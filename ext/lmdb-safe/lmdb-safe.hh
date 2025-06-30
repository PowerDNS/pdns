#pragma once
#include <string_view>
#include <lmdb.h>
#include <iostream>
#include <fstream>
#include <set>
#include <map>
#include <thread>
#include <memory>
#include <string>
#include <string.h>
#include <mutex>
#include <vector>
#include <algorithm>
#include <string>
#include <string_view>

#include "config.h"

#ifndef DNSDIST
#include <boost/range/detail/common.hpp>
#include <stdint.h>
#include <netinet/in.h>
#include <stdexcept>
#include "../../pdns/misc.hh"
#endif

using std::string_view;
using std::string;

#if BOOST_VERSION >= 106100
#define StringView string_view
#else
#define StringView string
#endif

/* open issues:
 *
 * - missing convenience functions (string_view, string)
 */

/*
The error strategy. Anything that "should never happen" turns into an exception. But things like 'duplicate entry' or 'no such key' are for you to deal with.
 */

/*
  Thread safety: we are as safe as lmdb. You can talk to MDBEnv from as many threads as you want
*/

/** MDBDbi is our only 'value type' object, as 1) a dbi is actually an integer
    and 2) per LMDB documentation, we never close it. */
class MDBDbi
{
public:
  MDBDbi(): d_dbi(-1)
  {
  }
  explicit MDBDbi(MDB_env* env, MDB_txn* txn, string_view dbname, int flags);

  operator const MDB_dbi&() const
  {
    return d_dbi;
  }

  MDB_dbi d_dbi;
};

class MDBRWTransactionImpl;
class MDBROTransactionImpl;

using MDBROTransaction = std::unique_ptr<MDBROTransactionImpl>;
using MDBRWTransaction = std::unique_ptr<MDBRWTransactionImpl>;

class MDBEnv
{
public:
  MDBEnv(const char* fname, int flags, int mode, uint64_t mapsizeMB);

  ~MDBEnv()
  {
    //    Only a single thread may call this function. All transactions, databases, and cursors must already be closed before calling this function
    mdb_env_close(d_env);
    // but, elsewhere, docs say database handles do not need to be closed?
  }

  MDBDbi openDB(const string_view dbname, int flags);

  MDBRWTransaction getRWTransaction();
  MDBROTransaction getROTransaction();

  operator MDB_env*& ()
  {
    return d_env;
  }
  MDB_env* d_env;

  int getRWTX();
  void incRWTX();
  void decRWTX();
  int getROTX();
  void incROTX();
  void decROTX();
private:
  std::mutex d_openmut;
  std::mutex d_countmutex;
  std::map<std::thread::id, int> d_RWtransactionsOut;
  std::map<std::thread::id, int> d_ROtransactionsOut;
};

std::shared_ptr<MDBEnv> getMDBEnv(const char* fname, int flags, int mode, uint64_t mapsizeMB);

#ifndef DNSDIST

#if !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || !defined(__ORDER_BIG_ENDIAN__)
#error "your compiler did not define byte order macros"
#endif

// FIXME do something more portable than __builtin_bswap64
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define _LMDB_SAFE_BSWAP64MAYBE(x) __builtin_bswap64(x)
#else
#define _LMDB_SAFE_BSWAP64MAYBE(x) (x)
#endif

struct MDBOutVal; // forward declaration because of how the functions below tie in with MDBOutVal

namespace LMDBLS {
  class __attribute__((__packed__)) LSheader {
  public:
    uint64_t d_timestamp;
    uint64_t d_txnid;
    uint8_t d_version;
    uint8_t d_flags;
    uint32_t d_reserved;
    uint16_t d_numextra;

    LSheader(uint64_t timestamp, uint64_t txnid, uint8_t flags=0, uint8_t version=0, uint8_t numextra=0):
      d_timestamp(_LMDB_SAFE_BSWAP64MAYBE(timestamp)),
      d_txnid(_LMDB_SAFE_BSWAP64MAYBE(txnid)),
      d_version(version),
      d_flags(flags),
      d_reserved(0),
      d_numextra(htons(numextra))
    {

    }

    std::string toString() {
      return std::string((char*)this, sizeof(*this)) + std::string(ntohs(d_numextra)*8, '\0');
    }

    uint64_t getTimestamp() const {
      return _LMDB_SAFE_BSWAP64MAYBE(d_timestamp);
    }
  };

  static_assert(sizeof(LSheader)==24, "LSheader size is wrong");

  const size_t LS_MIN_HEADER_SIZE = sizeof(LSheader);
  const size_t LS_BLOCK_SIZE = 8;
  const size_t LS_NUMEXTRA_OFFSET = 22;
  const uint8_t LS_FLAG_DELETED = 0x01;

  const LSheader* LSassertFixedHeaderSize(std::string_view val);
  size_t LScheckHeaderAndGetSize(std::string_view val, size_t datasize=0);
  size_t LScheckHeaderAndGetSize(const MDBOutVal *val, size_t datasize=0);
  bool LSisDeleted(std::string_view val);
  uint64_t LSgetTimestamp(std::string_view val);

  extern bool s_flag_deleted;
}

#undef _LMDB_SAFE_BSWAP64MAYBE

#endif /* ifndef DNSDIST */


struct MDBOutVal
{
  operator MDB_val&()
  {
    return d_mdbval;
  }

#ifndef DNSDIST
  template <class T,
          typename std::enable_if<std::is_integral<T>::value,
                                  T>::type* = nullptr> const
  T get()
  {
    T ret;

    size_t offset = LMDBLS::LScheckHeaderAndGetSize(this, sizeof(T));

    memcpy(&ret, reinterpret_cast<const char *>(d_mdbval.mv_data)+offset, sizeof(T));

    static_assert(sizeof(T) == 4, "this code currently only supports 32 bit integers");
    ret = ntohl(ret);
    return ret;
  }

  template <class T,
          typename std::enable_if<std::is_integral<T>::value,
                                  T>::type* = nullptr> const
  T getNoStripHeader()
  {
    T ret;
    if(d_mdbval.mv_size != sizeof(T))
      throw std::runtime_error("MDB data has wrong length for type");

    memcpy(&ret, d_mdbval.mv_data, sizeof(T));

    static_assert(sizeof(T) == 4, "this code currently only supports 32 bit integers");
    ret = ntohl(ret);
    return ret;
  }

#endif /* ifndef DNSDIST */

  template <class T,
            typename std::enable_if<std::is_class<T>::value,T>::type* = nullptr>
  T get() const;


#ifndef DNSDIST
  template <class T,
            typename std::enable_if<std::is_class<T>::value,T>::type* = nullptr>
  T getNoStripHeader() const;
#endif

  MDB_val d_mdbval;
};

template<> inline std::string MDBOutVal::get<std::string>() const
{
#ifndef DNSDIST
  size_t offset = LMDBLS::LScheckHeaderAndGetSize(this);

  return std::string((char*)d_mdbval.mv_data+offset, d_mdbval.mv_size-offset);
}

template<> inline std::string MDBOutVal::getNoStripHeader<std::string>() const
{
#endif
  return std::string((char*)d_mdbval.mv_data, d_mdbval.mv_size);
}

template<> inline string_view MDBOutVal::get<string_view>() const
{
#ifndef DNSDIST
  size_t offset = LMDBLS::LScheckHeaderAndGetSize(this);

  return string_view((char*)d_mdbval.mv_data+offset, d_mdbval.mv_size-offset);
}

template<> inline string_view MDBOutVal::getNoStripHeader<string_view>() const
{
#endif
  return string_view((char*)d_mdbval.mv_data, d_mdbval.mv_size);
}

class MDBInVal
{
public:
  MDBInVal(const MDBOutVal& rhs): d_mdbval(rhs.d_mdbval)
  {
  }

#ifndef DNSDIST
  template <class T,
            typename std::enable_if<std::is_integral<T>::value,
                                    T>::type* = nullptr>
  MDBInVal(T i)
  {
    static_assert(sizeof(T) == 4, "this code currently only supports 32 bit integers");
    auto j = htonl(i);    // all actual usage in our codebase is 32 bits. If that ever changes, this will break the build and avoid runtime surprises
    memcpy(&d_memory[0], &j, sizeof(j));

    d_mdbval.mv_size = sizeof(T);
    d_mdbval.mv_data = d_memory;;
  }
#endif

  MDBInVal(const char* s)
  {
    d_mdbval.mv_size = strlen(s);
    d_mdbval.mv_data = (void*)s;
  }

  MDBInVal(const string_view& v)
  {
    d_mdbval.mv_size = v.size();
    d_mdbval.mv_data = (void*)&v[0];
  }

  MDBInVal(const std::string& v)
  {
    d_mdbval.mv_size = v.size();
    d_mdbval.mv_data = (void*)&v[0];
  }


  template<typename T>
  static MDBInVal fromStruct(const T& t)
  {
    MDBInVal ret;
    ret.d_mdbval.mv_size = sizeof(T);
    ret.d_mdbval.mv_data = (void*)&t;
    return ret;
  }

  template <class T>
  T get() const;

  operator MDB_val&()
  {
    return d_mdbval;
  }
  MDB_val d_mdbval;
private:
  MDBInVal(){}
#ifndef DNSDIST
  char d_memory[sizeof(double)];
#endif
};

template <>
inline std::string MDBInVal::get<std::string>() const
{
  return {static_cast<char*>(d_mdbval.mv_data), d_mdbval.mv_size};
}

class MDBROCursor;

class MDBROTransactionImpl
{
protected:
  MDBROTransactionImpl(MDBEnv *parent, MDB_txn *txn);

private:
  static MDB_txn *openROTransaction(MDBEnv *env, MDB_txn *parent, int flags=0);

  MDBEnv* d_parent;
  std::vector<MDBROCursor*> d_cursors;

protected:
  MDB_txn* d_txn;

  void closeROCursors();

public:
  explicit MDBROTransactionImpl(MDBEnv* parent, int flags=0);

  MDBROTransactionImpl(const MDBROTransactionImpl& src) = delete;
  MDBROTransactionImpl &operator=(const MDBROTransactionImpl& src) = delete;

  // The move constructor/operator cannot be made safe due to Object Slicing with MDBRWTransaction.
  MDBROTransactionImpl(MDBROTransactionImpl&& rhs) = delete;
  MDBROTransactionImpl &operator=(MDBROTransactionImpl &&rhs) = delete;

  virtual ~MDBROTransactionImpl();

  virtual void abort();
  virtual void commit();

  int get(MDB_dbi dbi, const MDBInVal& key, MDBOutVal& val)
  {
    if(!d_txn)
      throw std::runtime_error("Attempt to use a closed RO transaction for get");

    int rc = mdb_get(d_txn, dbi, const_cast<MDB_val*>(&key.d_mdbval),
                     const_cast<MDB_val*>(&val.d_mdbval));

    if(rc && rc != MDB_NOTFOUND) {
      throw std::runtime_error("getting data: " + std::string(mdb_strerror(rc)));
    }

#ifndef DNSDIST
    if(rc != MDB_NOTFOUND) {  // key was found, value was retrieved
      std::string sval = val.getNoStripHeader<std::string>();
      if (LMDBLS::LSisDeleted(sval)) {  // but it was deleted
        rc = MDB_NOTFOUND;
      }
    }
#endif

    return rc;
  }

  int get(MDB_dbi dbi, const MDBInVal& key, string_view& val)
  {
    MDBOutVal out;
    int rc = get(dbi, key, out);
    if(!rc)
      val = out.get<string_view>();
    return rc;
  }


  // this is something you can do, readonly
  MDBDbi openDB(string_view dbname, int flags)
  {
    return MDBDbi( d_parent->d_env, d_txn, dbname, flags);
  }

  MDBROCursor getCursor(const MDBDbi&);
  MDBROCursor getROCursor(const MDBDbi&);

  operator MDB_txn*()
  {
    return d_txn;
  }

  inline operator bool() const {
    return d_txn;
  }

  inline MDBEnv &environment()
  {
    return *d_parent;
  }
};

/*
   A cursor in a read-only transaction must be closed explicitly, before or after its transaction ends. It can be reused with mdb_cursor_renew() before finally closing it.

   "If the parent transaction commits, the cursor must not be used again."
*/

template<class Transaction, class T>
class MDBGenCursor
{
private:
  std::vector<T*> *d_registry;
  MDB_cursor* d_cursor{nullptr};
  std::string d_prefix{""};
public:
  MDB_txn* d_txn{nullptr}; // ew, public
  uint64_t d_txtime{0};

  MDBGenCursor():
    d_registry(nullptr),
    d_cursor(nullptr),
    d_txn(nullptr)
  {

  }

  MDBGenCursor(std::vector<T*> &registry, MDB_cursor *cursor, MDB_txn *txn=nullptr, uint64_t txtime=0):
    d_registry(&registry),
    d_cursor(cursor),
    d_txn(txn),
    d_txtime(txtime)
  {
    registry.emplace_back(static_cast<T*>(this));
  }

private:
  void move_from(MDBGenCursor *src)
  {
    if (!d_registry) {
      return;
    }

    auto iter = std::find(d_registry->begin(),
                          d_registry->end(),
                          src);
    if (iter != d_registry->end()) {
      *iter = static_cast<T*>(this);
    } else {
      d_registry->emplace_back(static_cast<T*>(this));
    }
  }

public:
  MDBGenCursor(const MDBGenCursor &src) = delete;

  MDBGenCursor(MDBGenCursor &&src) noexcept:
    d_registry(src.d_registry),
    d_cursor(src.d_cursor)
  {
    move_from(&src);
    src.d_registry = nullptr;
    src.d_cursor = nullptr;
  }

  MDBGenCursor &operator=(const MDBGenCursor &src) = delete;

  MDBGenCursor &operator=(MDBGenCursor &&src) noexcept
  {
    d_registry = src.d_registry;
    d_cursor = src.d_cursor;
    move_from(&src);
    src.d_registry = nullptr;
    src.d_cursor = nullptr;
    return *this;
  }

  ~MDBGenCursor()
  {
    close();
  }

  /*
   to support (skip) entries marked deleted=1 in the LS header, we need to do some magic here
   this table notes, for each cursor op:
   * the maximum number of entries we may need to look at (1 or inf)
   * the subsequent op that needs to be done to skip over a deleted entry (or MDB_NOTFOUND to give up and say no)
   (table partially copied from http://www.lmdb.tech/doc/group__mdb.html#ga1206b2af8b95e7f6b0ef6b28708c9127 which I hope is a stable URL)
   (ops only relevant for DUPSORT/DUPFIXED have been omitted)
   (table is grouped by "skip op")

  | base op            | maxentries | skip op      | doc description of base op
  | MDB_FIRST          | inf        | MDB_NEXT     | Position at first key/data item
  | MDB_NEXT           | inf        | MDB_NEXT     | Position at next data item
  | MDB_SET_RANGE      | inf        | MDB_NEXT     | Position at first key greater than or equal to specified key.
  | MDB_LAST           | inf        | MDB_PREV     | Position at last key/data item
  | MDB_PREV           | inf        | MDB_PREV     | Position at previous data item
  | MDB_GET_CURRENT    | 1          | MDB_NOTFOUND | Return key/data at current cursor position
  | MDB_SET            | 1          | MDB_NOTFOUND | Position at specified key
  | MDB_SET_KEY        | 1          | MDB_NOTFOUND | Position at specified key, return key + data
  */

private:
  int skipDeleted(MDBOutVal& key, MDBOutVal& data, MDB_cursor_op op, int rc)
  {
#ifndef DNSDIST
    // when we get here
    // * mdb_cursor_get has been called once
    // * it did not return an error, but it might have returned MDB_NOTFOUND
    // * if it returned MDB_NOTFOUND, there is nothing for us to do and we pass that on

    if (rc == MDB_NOTFOUND) {
      return rc;
    }

    // when we get here
    // * mdb_cursor_get has been called at least once
    // * it found an entry, as far as LMDB is concerned, so key+data contain something
    // * but that might be a LS deleted=1 entry
    // * we know the cursor op that got us here

    while (true) {
      auto sval = data.getNoStripHeader<std::string_view>();
      if (d_prefix.length() > 0 && key.getNoStripHeader<StringView>().rfind(d_prefix, 0) != 0) {
        return MDB_NOTFOUND;
      }

      if (!LMDBLS::LSisDeleted(sval)) {
        // done!

        return rc;
      }

      // the found entry is set deleted, so we need to do something

      // if this was a 1-entry op, this is the end
      if (op == MDB_GET_CURRENT || op == MDB_SET || op == MDB_SET_KEY) {
        return MDB_NOTFOUND;
      }

      // otherwise, we need to try to carry on
      // all ops that do not map to NOTFOUND map to NEXT or PREV, including NEXT and PREV themselves
      // so we just override the op to NEXT or PREV
      if (op == MDB_FIRST || op == MDB_NEXT || op == MDB_SET_RANGE) {
        op = MDB_NEXT;
      }
      else if (op == MDB_LAST || op == MDB_PREV) {
        op = MDB_PREV;
      }
      else {
        throw std::runtime_error("got unsupported mdb cursor op");
      }

      rc = mdb_cursor_get(d_cursor, &key.d_mdbval, &data.d_mdbval, op);
      if(rc && rc != MDB_NOTFOUND) {
         throw std::runtime_error("Unable to get from cursor: " + std::string(mdb_strerror(rc)));
      }

      if (rc == MDB_NOTFOUND) {
        // we ended up finding nothing, so tell the caller
        return rc;
      }

      // when we get here
      // * the situation is just like the last time I wrote "when we get here"
      // * except mdb_cursor_get has been called at least twice
      // * so let's go back
    }
#else /* ifndef DNSDIST */
    return rc;
#endif
  }

public:
  int get(MDBOutVal& key, MDBOutVal& data, MDB_cursor_op op)
  {
    d_prefix.clear();
    int rc = mdb_cursor_get(d_cursor, &key.d_mdbval, &data.d_mdbval, op);
    if(rc && rc != MDB_NOTFOUND)
       throw std::runtime_error("Unable to get from cursor: " + std::string(mdb_strerror(rc)));
    return skipDeleted(key, data, op, rc);
  }

  int find(const MDBInVal& in, MDBOutVal& key, MDBOutVal& data)
  {
    d_prefix.clear();
    key.d_mdbval = in.d_mdbval;
    int rc=mdb_cursor_get(d_cursor, const_cast<MDB_val*>(&key.d_mdbval), &data.d_mdbval, MDB_SET);
    if(rc && rc != MDB_NOTFOUND)
       throw std::runtime_error("Unable to find from cursor: " + std::string(mdb_strerror(rc)));
    return skipDeleted(key, data, MDB_SET, rc);
  }

  int prefix(const MDBInVal& in, MDBOutVal& key, MDBOutVal& data)
  {
    d_prefix = in.get<string>();
    return _lower_bound(in, key, data);
  }

  int lower_bound(const MDBInVal& in, MDBOutVal& key, MDBOutVal& data)
  {
    d_prefix.clear();
    return _lower_bound(in, key, data);
  }

  int _lower_bound(const MDBInVal& in, MDBOutVal& key, MDBOutVal& data) // used by prefix() and lower_bound()
  {
    key.d_mdbval = in.d_mdbval;

    int rc = mdb_cursor_get(d_cursor, const_cast<MDB_val*>(&key.d_mdbval), &data.d_mdbval, MDB_SET_RANGE);
    if(rc && rc != MDB_NOTFOUND)
       throw std::runtime_error("Unable to lower_bound from cursor: " + std::string(mdb_strerror(rc)));
    return skipDeleted(key, data, MDB_SET_RANGE, rc);
  }


  int nextprev(MDBOutVal& key, MDBOutVal& data, MDB_cursor_op op)
  {
    int rc = mdb_cursor_get(d_cursor, const_cast<MDB_val*>(&key.d_mdbval), &data.d_mdbval, op);
    if(rc && rc != MDB_NOTFOUND)
       throw std::runtime_error("Unable to prevnext from cursor: " + std::string(mdb_strerror(rc)));
    return skipDeleted(key, data, op, rc);
  }

  int next(MDBOutVal& key, MDBOutVal& data)
  {
    return nextprev(key, data, MDB_NEXT);
  }

  int prev(MDBOutVal& key, MDBOutVal& data)
  {
    return nextprev(key, data, MDB_PREV);
  }

  int currentlast(MDBOutVal& key, MDBOutVal& data, MDB_cursor_op op)
  {
    int rc = mdb_cursor_get(d_cursor, const_cast<MDB_val*>(&key.d_mdbval), &data.d_mdbval, op);
    if(rc && rc != MDB_NOTFOUND)
       throw std::runtime_error("Unable to next from cursor: " + std::string(mdb_strerror(rc)));
    return skipDeleted(key, data, op, rc);
  }

  int current(MDBOutVal& key, MDBOutVal& data)
  {
    return currentlast(key, data, MDB_GET_CURRENT);
  }
  int last(MDBOutVal& key, MDBOutVal& data)
  {
    return currentlast(key, data, MDB_LAST);
  }
  int first(MDBOutVal& key, MDBOutVal& data)
  {
    return currentlast(key, data, MDB_FIRST);
  }

  operator MDB_cursor*()
  {
    return d_cursor;
  }

  operator bool() const
  {
    return d_cursor;
  }

  void close()
  {
    if (d_registry) {
      auto iter = std::find(d_registry->begin(),
                            d_registry->end(),
                            static_cast<T*>(this));
      if (iter != d_registry->end()) {
        d_registry->erase(iter);
      }
      d_registry = nullptr;
    }
    if (d_cursor) {
      mdb_cursor_close(d_cursor);
      d_cursor = nullptr;
    }
  }
};

class MDBROCursor : public MDBGenCursor<MDBROTransactionImpl, MDBROCursor>
{
public:
  MDBROCursor() = default;
  using MDBGenCursor<MDBROTransactionImpl, MDBROCursor>::MDBGenCursor;
  MDBROCursor(const MDBROCursor &src) = delete;
  MDBROCursor(MDBROCursor &&src) = default;
  MDBROCursor &operator=(const MDBROCursor &src) = delete;
  MDBROCursor &operator=(MDBROCursor &&src) = default;
  ~MDBROCursor() = default;

};

class MDBRWCursor;

class MDBRWTransactionImpl: public MDBROTransactionImpl
{
protected:
  MDBRWTransactionImpl(MDBEnv* parent, MDB_txn* txn);

private:
  static MDB_txn *openRWTransaction(MDBEnv* env, MDB_txn *parent, int flags);

private:
  std::vector<MDBRWCursor*> d_rw_cursors;

  uint64_t d_txtime{0};

  void closeRWCursors();
  inline void closeRORWCursors() {
    closeROCursors();
    closeRWCursors();
  }

public:
  explicit MDBRWTransactionImpl(MDBEnv* parent, int flags=0);

  MDBRWTransactionImpl(const MDBRWTransactionImpl& rhs) = delete;
  MDBRWTransactionImpl(MDBRWTransactionImpl&& rhs) = delete;
  MDBRWTransactionImpl &operator=(const MDBRWTransactionImpl& rhs) = delete;
  MDBRWTransactionImpl &operator=(MDBRWTransactionImpl&& rhs) = delete;

  ~MDBRWTransactionImpl() override;

  void commit() override;
  void abort() override;

  void clear(MDB_dbi dbi);

#ifndef DNSDIST
  void put(MDB_dbi dbi, const MDBInVal& key, const MDBInVal& val, int flags=0)
  {
    if(!d_txn)
      throw std::runtime_error("Attempt to use a closed RW transaction for put");
    int rc;

    size_t txid = mdb_txn_id(d_txn);

    if (d_txtime == 0) { throw std::runtime_error("got zero txtime"); }

    std::string ins =
      LMDBLS::LSheader(d_txtime, txid).toString()+
      std::string((const char*)val.d_mdbval.mv_data, val.d_mdbval.mv_size);

    MDBInVal pval = ins;

    if((rc=mdb_put(d_txn, dbi,
                   const_cast<MDB_val*>(&key.d_mdbval),
                   const_cast<MDB_val*>(&pval.d_mdbval), flags))) {
      throw std::runtime_error("putting data: " + std::string(mdb_strerror(rc)));
    }
  }
#else
  void put(MDB_dbi dbi, const MDBInVal& key, const MDBInVal& val, int flags=0)
  {
    if(!d_txn)
      throw std::runtime_error("Attempt to use a closed RW transaction for put");
    int rc;
    if((rc=mdb_put(d_txn, dbi,
                   const_cast<MDB_val*>(&key.d_mdbval),
                   const_cast<MDB_val*>(&val.d_mdbval), flags)))
      throw std::runtime_error("putting data: " + std::string(mdb_strerror(rc)));
  }
#endif

  int del(MDBDbi& dbi, const MDBInVal& key)
  {
    int rc;
    rc=mdb_del(d_txn, dbi, (MDB_val*)&key.d_mdbval, 0);
    if(rc && rc != MDB_NOTFOUND)
      throw std::runtime_error("deleting data: " + std::string(mdb_strerror(rc)));
#ifndef DNSDIST
    if(rc != MDB_NOTFOUND && LMDBLS::s_flag_deleted) {
      // if it did exist, we need to mark it as deleted now

      size_t txid = mdb_txn_id(d_txn);
      if (d_txtime == 0) { throw std::runtime_error("got zero txtime"); }

      std::string ins =
        // std::string((const char*)&txid, sizeof(txid)) +
        LMDBLS::LSheader(d_txtime, txid, LMDBLS::LS_FLAG_DELETED).toString();

      MDBInVal pval = ins;

      if((rc=mdb_put(d_txn, dbi,
                     const_cast<MDB_val*>(&key.d_mdbval),
                     const_cast<MDB_val*>(&pval.d_mdbval), 0))) {
              throw std::runtime_error("marking data deleted: " + std::string(mdb_strerror(rc)));
      }
    }
#endif
    return rc;
  }


  int get(MDBDbi& dbi, const MDBInVal& key, MDBOutVal& val)
  {
    if(!d_txn)
      throw std::runtime_error("Attempt to use a closed RW transaction for get");

    int rc = mdb_get(d_txn, dbi, const_cast<MDB_val*>(&key.d_mdbval),
                     const_cast<MDB_val*>(&val.d_mdbval));
    if(rc && rc != MDB_NOTFOUND) {
          throw std::runtime_error("getting data: " + std::string(mdb_strerror(rc)));
    }

#ifndef DNSDIST
    if(rc != MDB_NOTFOUND) {  // key was found, value was retrieved
      auto sval = val.getNoStripHeader<std::string_view>();
      if (LMDBLS::LSisDeleted(sval)) {  // but it was deleted
        rc = MDB_NOTFOUND;
      }
    }
#endif

    return rc;
  }

  MDBDbi openDB(string_view dbname, int flags)
  {
    return MDBDbi(environment().d_env, d_txn, dbname, flags);
  }

  MDBRWCursor getRWCursor(const MDBDbi&);
  MDBRWCursor getCursor(const MDBDbi&);

  MDBRWTransaction getRWTransaction();
  MDBROTransaction getROTransaction();

};

/* "A cursor in a write-transaction can be closed before its transaction ends, and will otherwise be closed when its transaction ends"
   This is a problem for us since it may means we are closing the cursor twice, which is bad
*/
class MDBRWCursor : public MDBGenCursor<MDBRWTransactionImpl, MDBRWCursor>
{
public:
  MDBRWCursor() = default;
  using MDBGenCursor<MDBRWTransactionImpl, MDBRWCursor>::MDBGenCursor;
  MDBRWCursor(const MDBRWCursor &src) = delete;
  MDBRWCursor(MDBRWCursor &&src) = default;
  MDBRWCursor &operator=(const MDBRWCursor &src) = delete;
  MDBRWCursor &operator=(MDBRWCursor &&src) = default;
  ~MDBRWCursor() = default;

#ifndef DNSDIST
  void put(const MDBOutVal& key, const MDBInVal& data)
  {
    size_t txid = mdb_txn_id(this->d_txn);

    if (d_txtime == 0) { throw std::runtime_error("got zero txtime"); }

    std::string ins =
      LMDBLS::LSheader(d_txtime, txid).toString()+
      std::string((const char*)data.d_mdbval.mv_data, data.d_mdbval.mv_size);

    MDBInVal pval = ins;

    int rc = mdb_cursor_put(*this,
                            const_cast<MDB_val*>(&key.d_mdbval),
                            const_cast<MDB_val*>(&pval.d_mdbval), MDB_CURRENT);
    if(rc)
      throw std::runtime_error("mdb_cursor_put: " + std::string(mdb_strerror(rc)));
  }
#else
  void put(const MDBOutVal& key, const MDBInVal& data)
  {
    int rc = mdb_cursor_put(*this,
                            const_cast<MDB_val*>(&key.d_mdbval),
                            const_cast<MDB_val*>(&data.d_mdbval), MDB_CURRENT);
    if(rc)
      throw std::runtime_error("mdb_cursor_put: " + std::string(mdb_strerror(rc)));
  }
#endif

#ifndef DNSDIST
  int del(int flags=0)
  {
    MDBOutVal key, val;

    if (LMDBLS::s_flag_deleted) {
      int rc_get = mdb_cursor_get (*this, &key.d_mdbval, &val.d_mdbval, MDB_GET_CURRENT);

      if(rc_get) {
              throw std::runtime_error("getting key to mark data as deleted: " + std::string(mdb_strerror(rc_get)));
      }

      size_t txid = mdb_txn_id(d_txn);
      if (d_txtime == 0) { throw std::runtime_error("got zero txtime"); }

      std::string ins =
        LMDBLS::LSheader(d_txtime, txid, LMDBLS::LS_FLAG_DELETED).toString();

      std::string skey((const char*)key.d_mdbval.mv_data, key.d_mdbval.mv_size);

      MDBInVal pkey = MDBInVal(skey);
      MDBInVal pval = ins;

      int rc_put = mdb_cursor_put(*this,
                     const_cast<MDB_val*>(&pkey.d_mdbval),
                     const_cast<MDB_val*>(&pval.d_mdbval), 0 /* MDB_CURRENT */);
      if(rc_put) {
              throw std::runtime_error("marking data deleted: " + std::string(mdb_strerror(rc_put)));
      }
      return rc_put;
    }
    else {
      // do a normal delete
      return mdb_cursor_del(*this, flags);
    }
  }
#endif
};
