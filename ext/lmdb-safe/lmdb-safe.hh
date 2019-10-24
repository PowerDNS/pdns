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

class MDBRWTransaction;
class MDBROTransaction;

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
  MDBInVal(const MDBOutVal& rhs): d_mdbval(rhs.d_mdbval)
  {
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

class MDBROTransaction
{
public:
  explicit MDBROTransaction(MDBEnv* parent, int flags=0);

  MDBROTransaction(MDBROTransaction&& rhs)
  {
    d_parent = rhs.d_parent;
    d_txn = rhs.d_txn;
    rhs.d_parent = 0;
    rhs.d_txn = 0;
  }

  void reset()
  {
    // this does not free cursors
    mdb_txn_reset(d_txn);
    d_parent->decROTX();
  }

  void renew()
  {
    if(d_parent->getROTX())
      throw std::runtime_error("Duplicate RO transaction");
    if(int rc = mdb_txn_renew(d_txn))
      throw std::runtime_error("Renewing RO transaction: "+std::string(mdb_strerror(rc)));
    d_parent->incROTX();
  }
  

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
    
  ~MDBROTransaction()
  {
    if(d_txn) {
      d_parent->decROTX();
      mdb_txn_commit(d_txn); // this appears to work better than abort for r/o database opening
    }
  }

  operator MDB_txn*&()
  {
    return d_txn;
  }
  
  MDBEnv* d_parent;
  MDB_txn* d_txn;
};

/* 
   A cursor in a read-only transaction must be closed explicitly, before or after its transaction ends. It can be reused with mdb_cursor_renew() before finally closing it. 

   "If the parent transaction commits, the cursor must not be used again."
*/

template<class Transaction>
class MDBGenCursor
{
public:
  MDBGenCursor(Transaction *t) : d_parent(t)
  {}
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

  operator MDB_cursor*&()
  {
    return d_cursor;
  }

  MDB_cursor* d_cursor{nullptr};
  Transaction* d_parent;
};

class MDBROCursor : public MDBGenCursor<MDBROTransaction>
{
public:
  MDBROCursor(MDBROTransaction* parent, const MDB_dbi& dbi) : MDBGenCursor<MDBROTransaction>(parent)
  {
    int rc= mdb_cursor_open(d_parent->d_txn, dbi, &d_cursor);
    if(rc) {
      throw std::runtime_error("Error creating RO cursor: "+std::string(mdb_strerror(rc)));
    }
  }
  MDBROCursor(MDBROCursor&& rhs) : MDBGenCursor<MDBROTransaction>(rhs.d_parent)
  {
    d_cursor = rhs.d_cursor;
    rhs.d_cursor = nullptr;
  }

  void close()
  {
    if (d_cursor) {
      mdb_cursor_close(d_cursor);
      d_cursor = nullptr;
    }
  }
  
  ~MDBROCursor()
  {
    if(d_cursor)
      mdb_cursor_close(d_cursor);
  }

};

class MDBRWCursor;

class MDBRWTransaction
{
public:
  explicit MDBRWTransaction(MDBEnv* parent, int flags=0);

  MDBRWTransaction(MDBRWTransaction&& rhs)
  {
    d_parent = rhs.d_parent;
    d_txn = rhs.d_txn;
    rhs.d_parent = 0;
    rhs.d_txn = 0;
  }

  MDBRWTransaction& operator=(MDBRWTransaction&& rhs)
  {
    if(d_txn)
      abort();

    d_parent = rhs.d_parent;
    d_txn = rhs.d_txn;
    rhs.d_parent = 0;
    rhs.d_txn = 0;
    
    return *this;
  }

  ~MDBRWTransaction()
  {
    if(d_txn) {
      d_parent->decRWTX();
      closeCursors();
      mdb_txn_abort(d_txn); // XXX check response?
    }
  }
  void closeCursors();
  
  void commit()
  {
    closeCursors();
    if(int rc = mdb_txn_commit(d_txn)) {
      throw std::runtime_error("committing: " + std::string(mdb_strerror(rc)));
    }
    d_parent->decRWTX();

    d_txn=0;
  }

  void abort()
  {
    closeCursors();
    mdb_txn_abort(d_txn); // XXX check error?
    d_txn = 0;
    d_parent->decRWTX();
  }

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
    return MDBDbi(d_parent->d_env, d_txn, dbname, flags);
  }

  MDBRWCursor getCursor(const MDBDbi&);

  void reportCursor(MDBRWCursor* child)
  {
    d_cursors.insert(child);
  }
  void unreportCursor(MDBRWCursor* child)
  {
    d_cursors.erase(child);
  }
  
  void reportCursorMove(MDBRWCursor* from, MDBRWCursor* to)
  {
    d_cursors.erase(from);
    d_cursors.insert(to);
  }
  
  operator MDB_txn*&()
  {
    return d_txn;
  }


  
  std::set<MDBRWCursor*> d_cursors;
  MDBEnv* d_parent;
  MDB_txn* d_txn;
};

/* "A cursor in a write-transaction can be closed before its transaction ends, and will otherwise be closed when its transaction ends" 
   This is a problem for us since it may means we are closing the cursor twice, which is bad
*/
class MDBRWCursor : public MDBGenCursor<MDBRWTransaction>
{
public:
  MDBRWCursor(MDBRWTransaction* parent, const MDB_dbi& dbi) : MDBGenCursor<MDBRWTransaction>(parent)
  {
    int rc= mdb_cursor_open(d_parent->d_txn, dbi, &d_cursor);
    if(rc) {
      throw std::runtime_error("Error creating RW cursor: "+std::string(mdb_strerror(rc)));
    }
    d_parent->reportCursor(this);
  }
  MDBRWCursor(MDBRWCursor&& rhs) : MDBGenCursor<MDBRWTransaction>(rhs.d_parent)
  {
    d_cursor = rhs.d_cursor;
    rhs.d_cursor = nullptr;
    d_parent->reportCursorMove(&rhs, this);
  }

  void close()
  {
    if(d_cursor)
      mdb_cursor_close(d_cursor);
    d_cursor = nullptr;
  }
  
  ~MDBRWCursor()
  {
    if(d_cursor)
      mdb_cursor_close(d_cursor);
    d_parent->unreportCursor(this);
  }


  void put(const MDBOutVal& key, const MDBInVal& data)
  {
    int rc = mdb_cursor_put(d_cursor,
                          const_cast<MDB_val*>(&key.d_mdbval),
                          const_cast<MDB_val*>(&data.d_mdbval), MDB_CURRENT);
    if(rc)
      throw std::runtime_error("mdb_cursor_put: " + std::string(mdb_strerror(rc)));
  }

  
  int put(const MDBOutVal& key, const MDBOutVal& data, int flags=0)
  {
    // XXX check errors
    return mdb_cursor_put(d_cursor,
                          const_cast<MDB_val*>(&key.d_mdbval),
                          const_cast<MDB_val*>(&data.d_mdbval), flags);
  }

  int del(int flags=0)
  {
    return mdb_cursor_del(d_cursor, flags);
  }
};

