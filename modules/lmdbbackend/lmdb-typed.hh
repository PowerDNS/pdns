#pragma once
#include <iostream>
#include "lmdb-safe.hh"
#include <boost/archive/binary_oarchive.hpp>
#include <boost/archive/binary_iarchive.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/serialization/string.hpp>
#include <boost/serialization/utility.hpp>
#include <boost/iostreams/stream.hpp>
#include <boost/iostreams/stream_buffer.hpp>
#include <boost/iostreams/device/back_inserter.hpp>
#include <sstream>
// using std::cout;
// using std::endl;


/* 
   Open issues:

   Everything should go into a namespace
   What is an error? What is an exception?
   could id=0 be magic? ('no such id')
     yes
   Is boost the best serializer?
     good default
   Perhaps use the separate index concept from multi_index
   perhaps get eiter to be of same type so for(auto& a : x) works
     make it more value "like" with unique_ptr
*/


/** Return the highest ID used in a database. Returns 0 for an empty DB.
    This makes us start everything at ID=1, which might make it possible to 
    treat id 0 as special
*/
unsigned int MDBGetMaxID(MDBRWTransaction& txn, MDBDbi& dbi);

/** This is our serialization interface.
    You can define your own serToString for your type if you know better
*/
template<typename T>
std::string serToString(const T& t)
{
  std::string serial_str;
  boost::iostreams::back_insert_device<std::string> inserter(serial_str);
  boost::iostreams::stream<boost::iostreams::back_insert_device<std::string> > s(inserter);
  boost::archive::binary_oarchive oa(s, boost::archive::no_header | boost::archive::no_codecvt);
  
  oa << t;
  return serial_str;
}

template<typename T>
void serFromString(const string_view& str, T& ret)
{
  ret = T();

  boost::iostreams::array_source source(&str[0], str.size());
  boost::iostreams::stream<boost::iostreams::array_source> stream(source);
  boost::archive::binary_iarchive in_archive(stream, boost::archive::no_header|boost::archive::no_codecvt);
  in_archive >> ret;

  /*
  std::istringstream istr{str};
  boost::archive::binary_iarchive oi(istr,boost::archive::no_header|boost::archive::no_codecvt );
  oi >> ret;
  */
}


template <class T, class Enable>
inline std::string keyConv(const T& t);

template <class T, typename std::enable_if<std::is_arithmetic<T>::value,T>::type* = nullptr>
inline std::string keyConv(const T& t)
{
  return std::string((char*)&t, sizeof(t));
}

// this is how to override specific types.. it is ugly 
template<class T, typename std::enable_if<std::is_same<T, std::string>::value,T>::type* = nullptr>
inline std::string keyConv(const T& t)
{
  return t;
}


/** This is a struct that implements index operations, but 
    only the operations that are broadcast to all indexes.
    Specifically, to deal with databases with less than the maximum
    number of interfaces, this only includes calls that should be
    ignored for empty indexes.

    this only needs methods that must happen for all indexes at once
    so specifically, not size<t> or get<t>, people ask for those themselves, and
    should no do that on indexes that don't exist */

template<class Class,typename Type, typename Parent>
struct LMDBIndexOps
{
  explicit LMDBIndexOps(Parent* parent) : d_parent(parent){}
  void put(MDBRWTransaction& txn, const Class& t, uint32_t id, int flags=0)
  {
    txn.put(d_idx, keyConv(d_parent->getMember(t)), id, flags);
  }

  void del(MDBRWTransaction& txn, const Class& t, uint32_t id)
  {
    if(int rc = txn.del(d_idx, keyConv(d_parent->getMember(t)), id)) {
      throw std::runtime_error("Error deleting from index: " + std::string(mdb_strerror(rc)));
    }
  }

  void openDB(std::shared_ptr<MDBEnv>& env, string_view str, int flags)
  {
    d_idx = env->openDB(str, flags);
  }
  MDBDbi d_idx;
  Parent* d_parent;
};

/** This is an index on a field in a struct, it derives from the LMDBIndexOps */

template<class Class,typename Type,Type Class::*PtrToMember>
struct index_on : LMDBIndexOps<Class, Type, index_on<Class, Type, PtrToMember>>
{
  index_on() : LMDBIndexOps<Class, Type, index_on<Class, Type, PtrToMember>>(this)
  {}
  static Type getMember(const Class& c)
  {
    return c.*PtrToMember;
  }
  
  typedef Type type;
};

/** This is a calculated index */
template<class Class, typename Type, class Func>
struct index_on_function : LMDBIndexOps<Class, Type, index_on_function<Class, Type, Func> >
{
  index_on_function() : LMDBIndexOps<Class, Type, index_on_function<Class, Type, Func> >(this)
  {}
  static Type getMember(const Class& c)
  {
    Func f;
    return f(c);
  }

  typedef Type type;           
};

/** nop index, so we can fill our N indexes, even if you don't use them all */
struct nullindex_t
{
  template<typename Class>
  void put(MDBRWTransaction& txn, const Class& t, uint32_t id, int flags=0)
  {}
  template<typename Class>
  void del(MDBRWTransaction& txn, const Class& t, uint32_t id)
  {}
  
  void openDB(std::shared_ptr<MDBEnv>& env, string_view str, int flags)
  {
    
  }
  typedef uint32_t type; // dummy
};


/** The main class. Templatized only on the indexes and typename right now */
template<typename T, class I1=nullindex_t, class I2=nullindex_t, class I3 = nullindex_t, class I4 = nullindex_t>
class TypedDBI
{
public:
  TypedDBI(std::shared_ptr<MDBEnv> env, string_view name)
    : d_env(env), d_name(name)
  {
    d_main = d_env->openDB(name, MDB_CREATE | MDB_INTEGERKEY);

    // now you might be tempted to go all MPL on this so we can get rid of the
    // ugly macro. I'm not very receptive to that idea since it will make things
    // EVEN uglier.
#define openMacro(N) std::get<N>(d_tuple).openDB(d_env, std::string(name)+"_"#N, MDB_CREATE | MDB_DUPFIXED | MDB_DUPSORT);
    openMacro(0);
    openMacro(1);
    openMacro(2);
    openMacro(3);
#undef openMacro
  }

  
  // we get a lot of our smarts from this tuple, it enables get<0> etc
  typedef std::tuple<I1, I2, I3, I4> tuple_t; 
  tuple_t d_tuple;

  // We support readonly and rw transactions. Here we put the Readonly operations
  // which get sourced by both kinds of transactions
  template<class Parent>
  struct ReadonlyOperations
  {
    ReadonlyOperations(Parent& parent) : d_parent(parent)
    {}

    //! Number of entries in main database
    uint32_t size()
    {
      MDB_stat stat;
      mdb_stat(*d_parent.d_txn, d_parent.d_parent->d_main, &stat);
      return stat.ms_entries;
    }

    //! Number of entries in the various indexes - should be the same
    template<int N>
    uint32_t size()
    {
      MDB_stat stat;
      mdb_stat(*d_parent.d_txn, std::get<N>(d_parent.d_parent->d_tuple).d_idx, &stat);
      return stat.ms_entries;
    }

    //! Get item with id, from main table directly
    bool get(uint32_t id, T& t)
    {
      MDBOutVal data;
      if(d_parent.d_txn->get(d_parent.d_parent->d_main, id, data))
        return false;
      
      serFromString(data.get<std::string>(), t);
      return true;
    }

    //! Get item through index N, then via the main database
    template<int N>
    uint32_t get(const typename std::tuple_element<N, tuple_t>::type::type& key, T& out)
    {
      MDBOutVal id;
      if(!d_parent.d_txn->get(std::get<N>(d_parent.d_parent->d_tuple).d_idx, keyConv(key), id)) {
        if(get(id.get<uint32_t>(), out))
          return id.get<uint32_t>();
      }
      return 0;
    }

    //! Cardinality of index N
    template<int N>
    uint32_t cardinality()
    {
      auto cursor = d_parent.d_txn->getCursor(std::get<N>(d_parent.d_parent->d_tuple).d_idx);
      bool first = true;
      MDBOutVal key, data;
      uint32_t count = 0;
      while(!cursor.get(key, data, first ? MDB_FIRST : MDB_NEXT_NODUP)) {
        ++count;
        first=false;
      }
      return count;
    }

    //! End iterator type
    struct eiter_t
    {};

    // can be on main, or on an index
    // when on main, return data directly
    // when on index, indirect
    // we can be limited to one key, or iterate over entire database
    // iter requires you to put the cursor in the right place first!
    struct iter_t
    {
      explicit iter_t(Parent* parent, typename Parent::cursor_t&& cursor, bool on_index, bool one_key, bool end=false) :
        d_parent(parent),
        d_cursor(std::move(cursor)),
        d_on_index(on_index), // is this an iterator on main database or on index?
        d_one_key(one_key),   // should we stop at end of key? (equal range)
        d_end(end)
      {
        if(d_end)
          return;
        d_prefix.clear();
        
        if(d_cursor.get(d_key, d_id,  MDB_GET_CURRENT)) {
          d_end = true;
          return;
        }

        if(d_on_index) {
          if(d_parent->d_txn->get(d_parent->d_parent->d_main, d_id, d_data))
            throw std::runtime_error("Missing id in constructor");
          serFromString(d_data.get<std::string>(), d_t);
        }
        else
          serFromString(d_id.get<std::string>(), d_t);
      }

      explicit iter_t(Parent* parent, typename Parent::cursor_t&& cursor, const std::string& prefix) :
        d_parent(parent),
        d_cursor(std::move(cursor)),
        d_on_index(true), // is this an iterator on main database or on index?
        d_one_key(false),
        d_prefix(prefix),  
        d_end(false)
      {
        if(d_end)
          return;

        if(d_cursor.get(d_key, d_id,  MDB_GET_CURRENT)) {
          d_end = true;
          return;
        }

        if(d_on_index) {
          if(d_parent->d_txn->get(d_parent->d_parent->d_main, d_id, d_data))
            throw std::runtime_error("Missing id in constructor");
          serFromString(d_data.get<std::string>(), d_t);
        }
        else
          serFromString(d_id.get<std::string>(), d_t);
      }

      
      std::function<bool(const MDBOutVal&)> filter;
      void del()
      {
        d_cursor.del();
      }
      
      bool operator!=(const eiter_t& rhs) const
      {
        return !d_end;
      }
      
      bool operator==(const eiter_t& rhs) const
      {
        return d_end;
      }
      
      const T& operator*()
      {
        return d_t;
      }
      
      const T* operator->()
      {
        return &d_t;
      }

      // implements generic ++ or --
      iter_t& genoperator(MDB_cursor_op dupop, MDB_cursor_op op)
      {
        MDBOutVal data;
        int rc;
      next:;
        rc = d_cursor.get(d_key, d_id, d_one_key ? dupop : op);
        if(rc == MDB_NOTFOUND) {
          d_end = true;
        }
        else if(rc) {
          throw std::runtime_error("in genoperator, " + std::string(mdb_strerror(rc)));
        }
        else if(!d_prefix.empty() && d_key.get<std::string>().rfind(d_prefix, 0)!=0) {
          d_end = true;
        }
        else {
          if(d_on_index) {
            if(d_parent->d_txn->get(d_parent->d_parent->d_main, d_id, data))
              throw std::runtime_error("Missing id field");
            if(filter && !filter(data))
              goto next;
            
            serFromString(data.get<std::string>(), d_t);
          }
          else {
            if(filter && !filter(data))
              goto next;
                        
            serFromString(d_id.get<std::string>(), d_t);
          }
        }
        return *this;
      }

      iter_t& operator++()
      {
        return genoperator(MDB_NEXT_DUP, MDB_NEXT);
      }
      iter_t& operator--()
      {
        return genoperator(MDB_PREV_DUP, MDB_PREV);
      }

      // get ID this iterator points to
      uint32_t getID()
      {
        if(d_on_index)
          return d_id.get<uint32_t>();
        else
          return d_key.get<uint32_t>();
      }

      const MDBOutVal& getKey()
      {
        return d_key;
      }
      
      
      // transaction we are part of
      Parent* d_parent;
      typename Parent::cursor_t d_cursor;

      // gcc complains if I don't zero-init these, which is worrying XXX
      MDBOutVal d_key{{0,0}}, d_data{{0,0}}, d_id{{0,0}};
      bool d_on_index;
      bool d_one_key;
      std::string d_prefix;
      bool d_end{false};
      T d_t;
    };

    template<int N>
    iter_t genbegin(MDB_cursor_op op)
    {
      typename Parent::cursor_t cursor = d_parent.d_txn->getCursor(std::get<N>(d_parent.d_parent->d_tuple).d_idx);
      
      MDBOutVal out, id;
      
      if(cursor.get(out, id,  op)) {
                                             // on_index, one_key, end
        return iter_t{&d_parent, std::move(cursor), true, false, true};
      }

      return iter_t{&d_parent, std::move(cursor), true, false};
    };

    template<int N>
    iter_t begin()
    {
      return genbegin<N>(MDB_FIRST);
    }

    template<int N>
    iter_t rbegin()
    {
      return genbegin<N>(MDB_LAST);
    }

    iter_t begin()
    {
      typename Parent::cursor_t cursor = d_parent.d_txn->getCursor(d_parent.d_parent->d_main);
      
      MDBOutVal out, id;
      
      if(cursor.get(out, id,  MDB_FIRST)) {
                                              // on_index, one_key, end        
        return iter_t{&d_parent, std::move(cursor), false, false, true};
      }

      return iter_t{&d_parent, std::move(cursor), false, false};
    };

    eiter_t end()
    {
      return eiter_t();
    }

    // basis for find, lower_bound
    template<int N>
    iter_t genfind(const typename std::tuple_element<N, tuple_t>::type::type& key, MDB_cursor_op op)
    {
      typename Parent::cursor_t cursor = d_parent.d_txn->getCursor(std::get<N>(d_parent.d_parent->d_tuple).d_idx);

      std::string keystr = keyConv(key);
      MDBInVal in(keystr);
      MDBOutVal out, id;
      out.d_mdbval = in.d_mdbval;
      
      if(cursor.get(out, id,  op)) {
                                              // on_index, one_key, end        
        return iter_t{&d_parent, std::move(cursor), true, false, true};
      }

      return iter_t{&d_parent, std::move(cursor), true, false};
    };

    template<int N>
    iter_t find(const typename std::tuple_element<N, tuple_t>::type::type& key)
    {
      return genfind<N>(key, MDB_SET);
    }

    template<int N>
    iter_t lower_bound(const typename std::tuple_element<N, tuple_t>::type::type& key)
    {
      return genfind<N>(key, MDB_SET_RANGE);
    }


    //! equal range - could possibly be expressed through genfind
    template<int N>
    std::pair<iter_t,eiter_t> equal_range(const typename std::tuple_element<N, tuple_t>::type::type& key)
    {
      typename Parent::cursor_t cursor = d_parent.d_txn->getCursor(std::get<N>(d_parent.d_parent->d_tuple).d_idx);

      std::string keyString=keyConv(key);
      MDBInVal in(keyString);
      MDBOutVal out, id;
      out.d_mdbval = in.d_mdbval;
      
      if(cursor.get(out, id,  MDB_SET)) {
                                              // on_index, one_key, end        
        return {iter_t{&d_parent, std::move(cursor), true, true, true}, eiter_t()};
      }

      return {iter_t{&d_parent, std::move(cursor), true, true}, eiter_t()};
    };

    //! equal range - could possibly be expressed through genfind
    template<int N>
    std::pair<iter_t,eiter_t> prefix_range(const typename std::tuple_element<N, tuple_t>::type::type& key)
    {
      typename Parent::cursor_t cursor = d_parent.d_txn->getCursor(std::get<N>(d_parent.d_parent->d_tuple).d_idx);

      std::string keyString=keyConv(key);
      MDBInVal in(keyString);
      MDBOutVal out, id;
      out.d_mdbval = in.d_mdbval;
      
      if(cursor.get(out, id,  MDB_SET_RANGE)) {
                                              // on_index, one_key, end        
        return {iter_t{&d_parent, std::move(cursor), true, true, true}, eiter_t()};
      }

      return {iter_t(&d_parent, std::move(cursor), keyString), eiter_t()};
    };

    
    Parent& d_parent;
  };
  
  class ROTransaction : public ReadonlyOperations<ROTransaction>
  {
  public:
    explicit ROTransaction(TypedDBI* parent) : ReadonlyOperations<ROTransaction>(*this), d_parent(parent), d_txn(std::make_shared<MDBROTransaction>(d_parent->d_env->getROTransaction())) 
    {
    }

    explicit ROTransaction(TypedDBI* parent, std::shared_ptr<MDBROTransaction> txn) : ReadonlyOperations<ROTransaction>(*this), d_parent(parent), d_txn(txn) 
    {
    }

    
    ROTransaction(ROTransaction&& rhs) :
      ReadonlyOperations<ROTransaction>(*this), d_parent(rhs.d_parent),d_txn(std::move(rhs.d_txn))
      
    {
      rhs.d_parent = 0;
    }

    std::shared_ptr<MDBROTransaction> getTransactionHandle()
    {
      return d_txn;
    }
    
    typedef MDBROCursor cursor_t;

    TypedDBI* d_parent;
    std::shared_ptr<MDBROTransaction> d_txn;    
  };    

  
  class RWTransaction :  public ReadonlyOperations<RWTransaction>
  {
  public:
    explicit RWTransaction(TypedDBI* parent) : ReadonlyOperations<RWTransaction>(*this), d_parent(parent)
    {
      d_txn = std::make_shared<MDBRWTransaction>(d_parent->d_env->getRWTransaction());
    }

    explicit RWTransaction(TypedDBI* parent, std::shared_ptr<MDBRWTransaction> txn) : ReadonlyOperations<RWTransaction>(*this), d_parent(parent), d_txn(txn)
    {
    }

    
    RWTransaction(RWTransaction&& rhs) :
      ReadonlyOperations<RWTransaction>(*this),
      d_parent(rhs.d_parent), d_txn(std::move(rhs.d_txn))
    {
      rhs.d_parent = 0;
    }

    // insert something, with possibly a specific id
    uint32_t put(const T& t, uint32_t id=0)
    {
      int flags = 0;
      if(!id) {
        id = MDBGetMaxID(*d_txn, d_parent->d_main) + 1;
        flags = MDB_APPEND;
      }
      d_txn->put(d_parent->d_main, id, serToString(t), flags);

#define insertMacro(N) std::get<N>(d_parent->d_tuple).put(*d_txn, t, id);
      insertMacro(0);
      insertMacro(1);
      insertMacro(2);
      insertMacro(3);
#undef insertMacro

      return id;
    }

    // modify an item 'in place', plus update indexes
    void modify(uint32_t id, std::function<void(T&)> func)
    {
      T t;
      if(!this->get(id, t)) 
        throw std::runtime_error("Could not modify id "+std::to_string(id));
      func(t);
      
      del(id);  // this is the lazy way. We could test for changed index fields
      put(t, id);
    }

    //! delete an item, and from indexes
    void del(uint32_t id)
    {
      T t;
      if(!this->get(id, t)) 
        return;
      
      d_txn->del(d_parent->d_main, id);
      clearIndex(id, t);
    }

    //! clear database & indexes (by hand!)
    void clear()
    {
      auto cursor = d_txn->getCursor(d_parent->d_main);
      bool first = true;
      MDBOutVal key, data;
      while(!cursor.get(key, data, first ? MDB_FIRST : MDB_NEXT)) {
        first = false;
        T t;
        serFromString(data.get<std::string>(), t);
        clearIndex(key.get<uint32_t>(), t);
        cursor.del();
      }
    }

    //! commit this transaction
    void commit()
    {
      d_txn->commit();
    }

    //! abort this transaction
    void abort()
    {
      d_txn->abort();
    }

    typedef MDBRWCursor cursor_t;

    std::shared_ptr<MDBRWTransaction> getTransactionHandle()
    {
      return d_txn;
    }

    
  private:
    // clear this ID from all indexes
    void clearIndex(uint32_t id, const T& t)
    {
#define clearMacro(N) std::get<N>(d_parent->d_tuple).del(*d_txn, t, id);
      clearMacro(0);
      clearMacro(1);
      clearMacro(2);
      clearMacro(3);
#undef clearMacro      
    }

  public:
    TypedDBI* d_parent;
    std::shared_ptr<MDBRWTransaction> d_txn;
  };

  //! Get an RW transaction
  RWTransaction getRWTransaction()
  {
    return RWTransaction(this);
  }

  //! Get an RO transaction
  ROTransaction getROTransaction()
  {
    return ROTransaction(this);
  }

  //! Get an RW transaction
  RWTransaction getRWTransaction(std::shared_ptr<MDBRWTransaction> txn)
  {
    return RWTransaction(this, txn);
  }

  //! Get an RO transaction
  ROTransaction getROTransaction(std::shared_ptr<MDBROTransaction> txn)
  {
    return ROTransaction(this, txn);
  }

  std::shared_ptr<MDBEnv> getEnv()
  {
    return d_env;
  }
  
private:
  std::shared_ptr<MDBEnv> d_env;
  MDBDbi d_main;
  std::string d_name;
};





