#pragma once

#include <stdexcept>
#include <boost/archive/binary_oarchive.hpp>
#include <boost/archive/binary_iarchive.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/serialization/string.hpp>
#include <boost/serialization/utility.hpp>
#include <boost/iostreams/stream.hpp>
#include <boost/iostreams/stream_buffer.hpp>
#include <boost/iostreams/device/back_inserter.hpp>
#include <utility>
#include <string>

#include "lmdb-safe.hh"

/*
 * OPEN ISSUES:
 *
 * - Everything should go into a namespace.
 * - Decide on what is an error and what is an exception.
 * - Could id=0 be magic? (e.g. 'no such id') - yes.
 * - Is boost the best serializer? It's a good default.
 * - Perhaps use the separate index concept from multi_index.
 * - Perhaps get eiter to be of same type so that for(auto& a : x) works.
 *   - Make it more value-like with unique_ptr.
 */

/**
 * LMDB ID Vector Type.
 */
using LmdbIdVec = std::vector<uint32_t>;

/**
 * Return the highest ID used in a database. Returns 0 for an empty DB. This makes us
 * start everything at ID=1, which might make it possible to treat id 0 as special.
 */
uint32_t MDBGetMaxID(MDBRWTransaction& txn, MDBDbi& dbi);

/**
 * Return a randomly generated ID that is unique and not zero. May throw if the database
 * is very full.
 */
uint32_t MDBGetRandomID(MDBRWTransaction& txn, MDBDbi& dbi);

/**
 * This is our serialization interface. It can be specialized for other types.
 */
template <typename T>
std::string serializeToBuffer(const T& value)
{
  std::string buffer;
  boost::iostreams::back_insert_device<std::string> inserter(buffer);
  boost::iostreams::stream<boost::iostreams::back_insert_device<std::string>> inserterStream(inserter);
  boost::archive::binary_oarchive outputArchive(inserterStream, boost::archive::no_header | boost::archive::no_codecvt);
  outputArchive << value;
  return buffer;
}

template <typename T>
void deserializeFromBuffer(const string_view& buffer, T& value)
{
  value = T();
  boost::iostreams::array_source source(buffer.data(), buffer.size());
  boost::iostreams::stream<boost::iostreams::array_source> stream(source);
  boost::archive::binary_iarchive inputArchive(stream, boost::archive::no_header | boost::archive::no_codecvt);
  inputArchive >> value;
}

template <class T, class Enable>
inline std::string keyConv(const T& value);

template <class T, typename std::enable_if<std::is_arithmetic<T>::value, T>::type* = nullptr>
inline std::string keyConv(const T& value)
{
  return std::string{(char*)&value, sizeof(value)};
}

/**
 * keyConv specialization for std::string.
 */
template <class T, typename std::enable_if<std::is_same<T, std::string>::value, T>::type* = nullptr>
inline std::string keyConv(const T& value)
{
  return value;
}

namespace {
  inline MDBOutVal getKeyFromCombinedKey(MDBInVal combined) {
    if (combined.d_mdbval.mv_size < sizeof(uint32_t)) {
      throw std::runtime_error("combined key too short to get ID from");
    }

    MDBOutVal ret{};
    ret.d_mdbval.mv_data = combined.d_mdbval.mv_data;
    ret.d_mdbval.mv_size = combined.d_mdbval.mv_size - sizeof(uint32_t);
    return ret;
  }

  inline MDBOutVal getIDFromCombinedKey(MDBInVal combined) {
    if (combined.d_mdbval.mv_size < sizeof(uint32_t)) {
      throw std::runtime_error("combined key too short to get ID from");
    }

    MDBOutVal ret{};
    // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    ret.d_mdbval.mv_data = static_cast<char*>(combined.d_mdbval.mv_data) + combined.d_mdbval.mv_size - sizeof(uint32_t);
    ret.d_mdbval.mv_size = sizeof(uint32_t);
    return ret;
  }

  inline std::string makeCombinedKey(MDBInVal key, MDBInVal val)
  {
    std::string lenprefix(sizeof(uint16_t), '\0');
    std::string skey(static_cast<char*>(key.d_mdbval.mv_data), key.d_mdbval.mv_size);
    std::string sval(static_cast<char*>(val.d_mdbval.mv_data), val.d_mdbval.mv_size);

    if (val.d_mdbval.mv_size != 0 &&  // empty val case, for range queries
        val.d_mdbval.mv_size != sizeof(uint32_t)) {
      throw std::runtime_error("got wrong size value in makeCombinedKey");
    }

    uint16_t len = htons(skey.size());
    memcpy(lenprefix.data(), &len, sizeof(len));
    std::string scombined = lenprefix + skey + sval;

    return scombined;
  }
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

  void put(MDBRWTransaction& txn, const Class& type, uint32_t idVal, int flags = 0)
  {
    auto scombined = makeCombinedKey(keyConv(d_parent->getMember(type)), idVal);
    MDBInVal combined(scombined);

    // if the entry existed already, this will just update the timestamp/txid in the LS header. This is intentional, so objects and their indexes always get synced together.
    txn->put(d_idx, combined, std::string{}, flags);
  }

  void del(MDBRWTransaction& txn, const Class& type, uint32_t idVal)
  {
    auto scombined = makeCombinedKey(keyConv(d_parent->getMember(type)), idVal);
    MDBInVal combined(scombined);

    int errCode = txn->del(d_idx, combined);
    if (errCode != 0) {
      throw std::runtime_error("Error deleting from index: " + std::string(mdb_strerror(errCode)));
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

template <class Class, typename Type, Type Class::*PtrToMember>
struct index_on : LMDBIndexOps<Class, Type, index_on<Class, Type, PtrToMember>>
{
  index_on() :
    LMDBIndexOps<Class, Type, index_on<Class, Type, PtrToMember>>(this)
  {}
  static Type getMember(const Class& klass)
  {
    return klass.*PtrToMember;
  }

  using type = Type;
};

/** This is a calculated index */
template <class Class, typename Type, class Func>
struct index_on_function : LMDBIndexOps<Class, Type, index_on_function<Class, Type, Func>>
{
  index_on_function() :
    LMDBIndexOps<Class, Type, index_on_function<Class, Type, Func>>(this)
  {}
  static Type getMember(const Class& klass)
  {
    Func function;
    return function(klass);
  }

  using type = Type;
};

/** nop index, so we can fill our N indexes, even if you don't use them all */
struct nullindex_t
{
  template <typename Class>
  void put(MDBRWTransaction& /* txn */, const Class& /* t */, uint32_t /* id */, int /* flags */ = 0)
  {}
  template <typename Class>
  void del(MDBRWTransaction& /* txn */, const Class& /* t */, uint32_t /* id */)
  {}

  void openDB(std::shared_ptr<MDBEnv>& /* env */, string_view /* str */, int /* flags */)
  {
  }

  using type = uint32_t; // dummy
};

/** The main class. Templatized only on the indexes and typename right now */
template <typename T, class I1 = nullindex_t, class I2 = nullindex_t, class I3 = nullindex_t, class I4 = nullindex_t>
class TypedDBI
{
  // we get a lot of our smarts from this tuple, it enables get<0> etc
  using tuple_t = std::tuple<I1, I2, I3, I4>;
  tuple_t d_tuple;

private:
  template <uint8_t N>
  inline auto openDB(string_view& name)
  {
    std::get<N>(d_tuple).openDB(d_env, std::string(name) + "_" + std::to_string(N), MDB_CREATE);
  }

public:
  TypedDBI(std::shared_ptr<MDBEnv> env, string_view name) :
    d_env(std::move(env)), d_name(name)
  {
    d_main = d_env->openDB(name, MDB_CREATE);
    openDB<0>(name);
    openDB<1>(name);
    openDB<2>(name);
    openDB<3>(name);
  }

  // We support readonly and rw transactions. Here we put the Readonly operations
  // which get sourced by both kinds of transactions
  template <class Parent>
  struct ReadonlyOperations
  {
    ReadonlyOperations(Parent& parent) :
      d_parent(parent)
    {}

    // //! Number of entries in main database
    // uint32_t size()
    // {
    //   MDB_stat stat;
    //   mdb_stat(**d_parent.d_txn, d_parent.d_parent->d_main, &stat);
    //   return stat.ms_entries;
    // }

    // //! Number of entries in the various indexes - should be the same
    // template<int N>
    // uint32_t size()
    // {
    //   MDB_stat stat;
    //   mdb_stat(**d_parent.d_txn, std::get<N>(d_parent.d_parent->d_tuple).d_idx, &stat);
    //   return stat.ms_entries;
    // }

    //! Get item with id, from main table directly
    int get2(uint32_t itemId, T& value)
    {
      MDBOutVal data{};
      int rc;
      rc = (*d_parent.d_txn)->get(d_parent.d_parent->d_main, itemId, data);
      if (rc == 0) {
        deserializeFromBuffer(data.get<std::string>(), value);
      }
      return rc;
    }
    bool get(uint32_t itemId, T& value)
    {
      return get2(itemId, value) == 0;
    }

    //! Get item through index N, then via the main database
    template<int N>
    uint32_t get(const typename std::tuple_element<N, tuple_t>::type::type& key, T& out)
    {
      // MDBOutVal out;
      // uint32_t id;

      // auto range = (*d_parent.d_txn)->prefix_range<N>(domain);

      // auto range = prefix_range<N>(key);
      LmdbIdVec ids;

      // because we know we only want one item, pass onlyOldest=true to consistently get the same one out of a set of duplicates
      get_multi<N>(key, ids, true);

      switch (ids.size()) {
      case 0:
        return 0;
      case 1: {
        auto rc = get2(ids[0], out);
        if (rc == 0) {
          return ids[0];
        }
        if (rc == MDB_NOTFOUND) {
          /* element not present, or has been marked deleted */
          return 0;
        }
        throw std::runtime_error("in index get, failed (" + std::to_string(rc) + ")");
        break;
      }
      default:
        throw std::runtime_error("in index get, found more than one item");
      }
    }

    // //! Cardinality of index N
    // template<int N>
    // uint32_t cardinality()
    // {
    //   auto cursor = (*d_parent.d_txn)->getCursor(std::get<N>(d_parent.d_parent->d_tuple).d_idx);
    //   bool first = true;
    //   MDBOutVal key, data;
    //   uint32_t count = 0;
    //   while(!cursor.get(key, data, first ? MDB_FIRST : MDB_NEXT_NODUP)) {
    //     ++count;
    //     first=false;
    //   }
    //   return count;
    // }

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
        if(d_end) {
          return;
        }
        d_prefix.clear();

        if(d_cursor.get(d_key, d_id,  MDB_GET_CURRENT)) {
          d_end = true;
          return;
        }

        if (d_id.d_mdbval.mv_size < LMDBLS::LS_MIN_HEADER_SIZE) {
          throw std::runtime_error("got short value");
        }

        // MDBOutVal id = d_id;

        // id.d_mdbval.mv_size -= LS_HEADER_SIZE;
        // id.d_mdbval.mv_data = (char*)d_id.d_mdbval.mv_data + LS_HEADER_SIZE;

        if (d_on_index) {
          if ((*d_parent->d_txn)->get(d_parent->d_parent->d_main, d_id, d_data)) {
            throw std::runtime_error("Missing id in constructor");
          }
          deserializeFromBuffer(d_data.get<std::string>(), d_t);
        }
        else {
          deserializeFromBuffer(d_id.get<std::string>(), d_t);
        }
      }

      explicit iter_t(Parent* parent, typename Parent::cursor_t&& cursor, std::string prefix) :
        d_parent(parent),
        d_cursor(std::move(cursor)),
        d_on_index(true), // is this an iterator on main database or on index?
        d_one_key(false),
        d_prefix(std::move(prefix))
      {
        if (d_end) {
          return;
        }

        if (d_cursor.get(d_key, d_id, MDB_GET_CURRENT)) {
          d_end = true;
          return;
        }

        d_id = getIDFromCombinedKey(d_key);

        if (d_on_index) {
          if ((*d_parent->d_txn)->get(d_parent->d_parent->d_main, d_id, d_data)) {
            throw std::runtime_error("Missing id in constructor");
          }
          deserializeFromBuffer(d_data.get<std::string>(), d_t);
        }
        else {
          deserializeFromBuffer(d_id.get<std::string>(), d_t);
        }
      }

      // std::function<bool(const MDBOutVal&)> filter;
      void del()
      {
        d_cursor.del();
      }

      bool operator!=(const eiter_t& /* rhs */) const
      {
        return !d_end;
      }

      bool operator==(const eiter_t& /* rhs */) const
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
      iter_t& genoperator(MDB_cursor_op operation)
      {
        MDBOutVal data{};
        int rc = 0;
      // next:;
        if (!d_one_key) {
          rc = d_cursor.get(d_key, d_id, operation);
        }
        if(d_one_key || rc == MDB_NOTFOUND) {
          d_end = true;
        }
        else if(rc != 0) {
          throw std::runtime_error("in genoperator, " + std::string(mdb_strerror(rc)));
        }
        else if(!d_prefix.empty() &&
          // d_key.getNoStripHeader<std::string>().rfind(d_prefix, 0)!=0 &&
          getKeyFromCombinedKey(d_key).template getNoStripHeader<std::string>() != d_prefix) {
          d_end = true;
        }
        else {
          // if (d_id.d_mdbval.mv_size < LS_HEADER_SIZE) throw std::runtime_error("got short value");

          // MDBOutVal id = d_id;

          // id.d_mdbval.mv_size -= LS_HEADER_SIZE;
          // id.d_mdbval.mv_data = (char*)d_id.d_mdbval.mv_data+LS_HEADER_SIZE;

          if(d_on_index) {
            d_id = getIDFromCombinedKey(d_key);
            if ((*d_parent->d_txn)->get(d_parent->d_parent->d_main, d_id, data)) {
              throw std::runtime_error("Missing id field");
            }
            // if(filter && !filter(data))
            //   goto next;

            deserializeFromBuffer(data.get<std::string>(), d_t);
          }
          else {
            // if(filter && !filter(data))
            //   goto next;

            deserializeFromBuffer(d_id.get<std::string>(), d_t);
          }
        }
        return *this;
      }

      iter_t& operator++()
      {
        return genoperator(MDB_NEXT);
      }
      // iter_t& operator--()
      // {
      //   return genoperator(MDB_PREV);
      // }

      // get ID this iterator points to
      uint32_t getID()
      {
        if (d_on_index) {
          // return d_id.get<uint32_t>();
          return d_id.getNoStripHeader<uint32_t>();
        }
        return d_key.getNoStripHeader<uint32_t>();
      }

      const MDBOutVal& getKey()
      {
        return d_key;
      }

      // transaction we are part of
      Parent* d_parent;
      typename Parent::cursor_t d_cursor;

      // gcc complains if I don't zero-init these, which is worrying XXX
      MDBOutVal d_key{{0, nullptr}};
      MDBOutVal d_data{{0, nullptr}};
      MDBOutVal d_id{{0, nullptr}};
      bool d_on_index;
      bool d_one_key;
      std::string d_prefix;
      bool d_end{false};
      T d_t;
    };

    template<int N>
    iter_t genbegin(MDB_cursor_op operation)
    {
      typename Parent::cursor_t cursor = (*d_parent.d_txn)->getCursor(std::get<N>(d_parent.d_parent->d_tuple).d_idx);

      MDBOutVal out{};
      MDBOutVal id{};

      if(cursor.get(out, id,  operation)) {
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
      typename Parent::cursor_t cursor = (*d_parent.d_txn)->getCursor(d_parent.d_parent->d_main);

      MDBOutVal out{};
      MDBOutVal id{};

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
    iter_t genfind(const typename std::tuple_element<N, tuple_t>::type::type& key, MDB_cursor_op operation)
    {
      typename Parent::cursor_t cursor = (*d_parent.d_txn)->getCursor(std::get<N>(d_parent.d_parent->d_tuple).d_idx);

      std::string keystr = makeCombinedKey(keyConv(key), MDBInVal(""));
      MDBInVal in(keystr);
      MDBOutVal out{};
      MDBOutVal id{};
      out.d_mdbval = in.d_mdbval;

      if(cursor.get(out, id,  operation)) {
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
      typename Parent::cursor_t cursor = (*d_parent.d_txn)->getCursor(std::get<N>(d_parent.d_parent->d_tuple).d_idx);

      std::string keyString=makeCombinedKey(keyConv(key), MDBInVal(""));
      MDBInVal in(keyString);
      MDBOutVal out{};
      MDBOutVal id{};
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
      typename Parent::cursor_t cursor = (*d_parent.d_txn)->getCursor(std::get<N>(d_parent.d_parent->d_tuple).d_idx);

      std::string keyString=makeCombined(keyConv(key), MDBInVal(""));
      MDBInVal in(keyString);
      MDBOutVal out{};
      MDBOutVal id{};
      out.d_mdbval = in.d_mdbval;

      if(cursor.get(out, id,  MDB_SET_RANGE) ||
         getKeyFromCombinedKey(out).template getNoStripHeader<std::string>() != keyString) {
                                                    // on_index, one_key, end
        return {iter_t{&d_parent, std::move(cursor), true, true, true}, eiter_t()};
      }

      return {iter_t(&d_parent, std::move(cursor), keyString), eiter_t()};
    };

    template<int N>
    void get_multi(const typename std::tuple_element<N, tuple_t>::type::type& key, LmdbIdVec& ids, bool onlyOldest=false)
    {
      // std::cerr<<"in get_multi"<<std::endl;
      typename Parent::cursor_t cursor = (*d_parent.d_txn)->getCursor(std::get<N>(d_parent.d_parent->d_tuple).d_idx);

      std::string keyString=makeCombinedKey(keyConv(key), MDBInVal(""));
      MDBInVal in(keyString);
      MDBOutVal out{};
      MDBOutVal id{};
      out.d_mdbval = in.d_mdbval;

      int rc = cursor.get(out, id,  MDB_SET_RANGE);

      uint64_t oldestts = UINT64_MAX;
      uint32_t oldestid = 0;

      while (rc == 0) {
        auto sout = out.getNoStripHeader<std::string>(); // FIXME: this (and many others) could probably be string_view
        auto thiskey = getKeyFromCombinedKey(out);
        auto sthiskey = thiskey.getNoStripHeader<std::string>();

        if (sout.find(keyString) != 0) {
          // we are no longer in range, so we are done
          break;
        }

        if (sthiskey == keyString) {
          auto _id = getIDFromCombinedKey(out);
          uint64_t ts = LMDBLS::LSgetTimestamp(id.getNoStripHeader<string_view>());
          auto itemId = _id.getNoStripHeader<uint32_t>();

          if (onlyOldest) {
            if (ts < oldestts) {
              oldestts = ts;
              oldestid = itemId;

              ids.clear();
              ids.push_back(oldestid);
            }
          } else {
            ids.push_back(itemId);
          }
        }

        rc = cursor.get(out, id, MDB_NEXT);
      }

      if (rc != 0 && rc != MDB_NOTFOUND) {
        throw std::runtime_error("error during get_multi");
      }
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

    ROTransaction(ROTransaction&& rhs) noexcept :
      ReadonlyOperations<ROTransaction>(*this), d_parent(rhs.d_parent), d_txn(std::move(rhs.d_txn))
    {
      rhs.d_parent = 0;
    }

    std::shared_ptr<MDBROTransaction> getTransactionHandle()
    {
      return d_txn;
    }

    using cursor_t = MDBROCursor;

    TypedDBI* d_parent;
    std::shared_ptr<MDBROTransaction> d_txn;
  };

  class RWTransaction :  public ReadonlyOperations<RWTransaction>
  {
  private:
    template <uint8_t N>
    inline auto insert(const T& value, uint32_t itemId)
    {
      std::get<N>(d_parent->d_tuple).put(*d_txn, value, itemId);
    }

  public:
    explicit RWTransaction(TypedDBI* parent) :
      ReadonlyOperations<RWTransaction>(*this), d_parent(parent), d_txn(std::make_shared<MDBRWTransaction>(d_parent->d_env->getRWTransaction()))
    {
    }

    explicit RWTransaction(TypedDBI* parent, std::shared_ptr<MDBRWTransaction> txn) : ReadonlyOperations<RWTransaction>(*this), d_parent(parent), d_txn(txn)
    {
    }

    RWTransaction(RWTransaction&& rhs) noexcept :
      ReadonlyOperations<RWTransaction>(*this),
      d_parent(rhs.d_parent),
      d_txn(std::move(rhs.d_txn))
    {
      rhs.d_parent = 0;
    }

    // insert something, with possibly a specific id
    uint32_t put(const T& value, uint32_t itemId, bool random_ids=false)
    {
      int flags = 0;
      if(itemId == 0) {
        if(random_ids) {
          itemId = MDBGetRandomID(*d_txn, d_parent->d_main);
        }
        else {
          itemId = MDBGetMaxID(*d_txn, d_parent->d_main) + 1;
          // FIXME: after dropping MDB_INTEGERKEY, we had to drop MDB_APPEND here. Check if this is an LMDB quirk.
          // flags = MDB_APPEND;
        }
      }
      (*d_txn)->put(d_parent->d_main, itemId, serializeToBuffer(value), flags);

      insert<0>(value, itemId);
      insert<1>(value, itemId);
      insert<2>(value, itemId);
      insert<3>(value, itemId);

      return itemId;
    }

    // modify an item 'in place', plus update indexes
    void modify(uint32_t itemId, std::function<void(T&)> func)
    {
      T value;
      if (!this->get(itemId, value)) {
        throw std::runtime_error("Could not modify id " + std::to_string(itemId));
      }
      func(value);

      del(itemId);  // this is the lazy way. We could test for changed index fields
      put(value, itemId);
    }

    //! delete an item, and from indexes
    void del(uint32_t itemId)
    {
      T value;
      if (!this->get(itemId, value)) {
        return;
      }

      (*d_txn)->del(d_parent->d_main, itemId);
      clearIndex(itemId, value);
    }

    //! clear database & indexes (by hand!)
    void clear()
    {
      auto cursor = (*d_txn)->getRWCursor(d_parent->d_main);
      bool first = true;
      MDBOutVal key{};
      MDBOutVal data{};
      while(!cursor.get(key, data, first ? MDB_FIRST : MDB_NEXT)) {
        first = false;
        T value;
        deserializeFromBuffer(data.get<std::string>(), value);
        clearIndex(key.get<uint32_t>(), value);
        cursor.del();
      }
    }

    //! commit this transaction
    void commit()
    {
      (*d_txn)->commit();
    }

    //! abort this transaction
    void abort()
    {
      (*d_txn)->abort();
    }

    using cursor_t = MDBRWCursor;

    std::shared_ptr<MDBRWTransaction> getTransactionHandle()
    {
      return d_txn;
    }

  private:
    template <uint8_t N>
    inline auto clear(const T& value, uint32_t itemId)
    {
      std::get<N>(d_parent->d_tuple).del(*d_txn, value, itemId);
    }

    // clear this ID from all indexes
    void clearIndex(uint32_t itemId, const T& value)
    {
      clear<0>(value, itemId);
      clear<1>(value, itemId);
      clear<2>(value, itemId);
      clear<3>(value, itemId);
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
