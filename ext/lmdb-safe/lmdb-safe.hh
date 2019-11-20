#pragma once
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

// apple compiler somehow has string_view even in c++11!
#if __cplusplus < 201703L && !defined(__APPLE__)
#include <boost/version.hpp>
#if BOOST_VERSION >= 106100
#include <boost/utility/string_view.hpp>
using boost::string_view;
#else
#include <boost/utility/string_ref.hpp>
using string_view = boost::string_ref;
#endif
#else // C++17
using std::string_view;
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
  MDBDbi()
  {
    d_dbi = -1;
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
  MDBEnv(const char* fname, int flags, int mode);

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

std::shared_ptr<MDBEnv> getMDBEnv(const char* fname, int flags, int mode);



struct MDBOutVal
{
  operator MDB_val&()
  {
    return d_mdbval;
  }

  template <class T,
          typename std::enable_if<std::is_arithmetic<T>::value,
                                  T>::type* = nullptr> const
  T get()
  {
    T ret;
    if(d_mdbval.mv_size != sizeof(T))
      throw std::runtime_error("MDB data has wrong length for type");
    
    memcpy(&ret, d_mdbval.mv_data, sizeof(T));
    return ret;
  }

  template <class T,
            typename std::enable_if<std::is_class<T>::value,T>::type* = nullptr>
  T get() const;

  template<class T>
  T get_struct() const
  {
    T ret;
    if(d_mdbval.mv_size != sizeof(T))
      throw std::runtime_error("MDB data has wrong length for type");
    
    memcpy(&ret, d_mdbval.mv_data, sizeof(T));
    return ret;
  }

  template<class T>
  const T* get_struct_ptr() const
  {
    if(d_mdbval.mv_size != sizeof(T))
      throw std::runtime_error("MDB data has wrong length for type");
    
    return reinterpret_cast<const T*>(d_mdbval.mv_data);
  }
  
  
  MDB_val d_mdbval;
};

template<> inline std::string MDBOutVal::get<std::string>() const
{
  return std::string((char*)d_mdbval.mv_data, d_mdbval.mv_size);
}

template<> inline string_view MDBOutVal::get<string_view>() const
{
  return string_view((char*)d_mdbval.mv_data, d_mdbval.mv_size);
}

class MDBInVal
{
public:
  MDBInVal(const MDBOutVal& rhs)
  {
    d_mdbval = rhs.d_mdbval;
  }

  template <class T,
            typename std::enable_if<std::is_arithmetic<T>::value,
                                    T>::type* = nullptr>
  MDBInVal(T i) 
  {
    memcpy(&d_memory[0], &i, sizeof(i));
    d_mdbval.mv_size = sizeof(T);
    d_mdbval.mv_data = d_memory;;
  }

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
  
  operator MDB_val&()
  {
    return d_mdbval;
  }
  MDB_val d_mdbval;
private:
  MDBInVal(){}
  char d_memory[sizeof(double)];

};




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
    if(rc && rc != MDB_NOTFOUND)
      throw std::runtime_error("getting data: " + std::string(mdb_strerror(rc)));
    
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
  MDB_cursor* d_cursor;

public:
  MDBGenCursor():
    d_registry(nullptr),
    d_cursor(nullptr)
  {

  }

  MDBGenCursor(std::vector<T*> &registry, MDB_cursor *cursor):
    d_registry(&registry),
    d_cursor(cursor)
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

public:
  int get(MDBOutVal& key, MDBOutVal& data, MDB_cursor_op op)
  {
    int rc = mdb_cursor_get(d_cursor, &key.d_mdbval, &data.d_mdbval, op);
    if(rc && rc != MDB_NOTFOUND)
       throw std::runtime_error("Unable to get from cursor: " + std::string(mdb_strerror(rc)));
    return rc;
  }

  int find(const MDBInVal& in, MDBOutVal& key, MDBOutVal& data)
  {
    key.d_mdbval = in.d_mdbval;
    int rc=mdb_cursor_get(d_cursor, const_cast<MDB_val*>(&key.d_mdbval), &data.d_mdbval, MDB_SET);
    if(rc && rc != MDB_NOTFOUND)
       throw std::runtime_error("Unable to find from cursor: " + std::string(mdb_strerror(rc)));
    return rc;
  }
  
  int lower_bound(const MDBInVal& in, MDBOutVal& key, MDBOutVal& data)
  {
    key.d_mdbval = in.d_mdbval;

    int rc = mdb_cursor_get(d_cursor, const_cast<MDB_val*>(&key.d_mdbval), &data.d_mdbval, MDB_SET_RANGE);
    if(rc && rc != MDB_NOTFOUND)
       throw std::runtime_error("Unable to lower_bound from cursor: " + std::string(mdb_strerror(rc)));
    return rc;
  }

  
  int nextprev(MDBOutVal& key, MDBOutVal& data, MDB_cursor_op op)
  {
    int rc = mdb_cursor_get(d_cursor, const_cast<MDB_val*>(&key.d_mdbval), &data.d_mdbval, op);
    if(rc && rc != MDB_NOTFOUND)
       throw std::runtime_error("Unable to prevnext from cursor: " + std::string(mdb_strerror(rc)));
    return rc;
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
    return rc;
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


  int del(MDBDbi& dbi, const MDBInVal& key, const MDBInVal& val)
  {
    int rc;
    rc=mdb_del(d_txn, dbi, (MDB_val*)&key.d_mdbval, (MDB_val*)&val.d_mdbval);
    if(rc && rc != MDB_NOTFOUND)
      throw std::runtime_error("deleting data: " + std::string(mdb_strerror(rc)));
    return rc;
  }

  int del(MDBDbi& dbi, const MDBInVal& key)
  {
    int rc;
    rc=mdb_del(d_txn, dbi, (MDB_val*)&key.d_mdbval, 0);
    if(rc && rc != MDB_NOTFOUND)
      throw std::runtime_error("deleting data: " + std::string(mdb_strerror(rc)));
    return rc;
  }

 
  int get(MDBDbi& dbi, const MDBInVal& key, MDBOutVal& val)
  {
    if(!d_txn)
      throw std::runtime_error("Attempt to use a closed RW transaction for get");

    int rc = mdb_get(d_txn, dbi, const_cast<MDB_val*>(&key.d_mdbval),
                     const_cast<MDB_val*>(&val.d_mdbval));
    if(rc && rc != MDB_NOTFOUND)
      throw std::runtime_error("getting data: " + std::string(mdb_strerror(rc)));
    return rc;
  }

  int get(MDBDbi& dbi, const MDBInVal& key, string_view& val)
  {
    MDBOutVal out;
    int rc = get(dbi, key, out);
    if(!rc)
      val = out.get<string_view>();
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

  void put(const MDBOutVal& key, const MDBInVal& data)
  {
    int rc = mdb_cursor_put(*this,
                            const_cast<MDB_val*>(&key.d_mdbval),
                            const_cast<MDB_val*>(&data.d_mdbval), MDB_CURRENT);
    if(rc)
      throw std::runtime_error("mdb_cursor_put: " + std::string(mdb_strerror(rc)));
  }

  
  int put(const MDBOutVal& key, const MDBOutVal& data, int flags=0)
  {
    // XXX check errors
    return mdb_cursor_put(*this,
                          const_cast<MDB_val*>(&key.d_mdbval),
                          const_cast<MDB_val*>(&data.d_mdbval), flags);
  }

  int del(int flags=0)
  {
    return mdb_cursor_del(*this, flags);
  }

};

