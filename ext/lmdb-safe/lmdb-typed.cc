#include "lmdb-typed.hh"
#include "pdns/dns_random.hh"

uint32_t MDBGetMaxID(MDBRWTransaction& txn, MDBDbi& dbi)
{
  auto cursor = txn->getRWCursor(dbi);
  MDBOutVal maxidval{};
  MDBOutVal maxcontent{};
  uint32_t maxid{0};
  if (cursor.get(maxidval, maxcontent, MDB_LAST) == 0) {
    maxid = maxidval.getNoStripHeader<uint32_t>();
  }
  return maxid;
}

uint32_t MDBGetRandomID(MDBRWTransaction& txn, MDBDbi& dbi, uint32_t seed)
{
  auto cursor = txn->getRWCursor(dbi);
  uint32_t newID = seed & ~(1 << 31);
  for (int attempts = 0; attempts < 20; attempts++) {
    MDBOutVal key{};
    MDBOutVal content{};

    // dns_random generates a random number in [0..signed_int_max-1]. We add 1 to avoid 0
    // and allow type_max. 0 is avoided because the put() interface uses it to mean
    // "please allocate a number for me".
    if (seed == 0 || attempts > 0) {
      newID = dns_random(std::numeric_limits<signed int>::max()) + 1;
    }
    if (cursor.find(MDBInVal(newID), key, content) != 0) {
      return newID;
    }
  }
  throw std::runtime_error("MDBGetRandomID() could not assign an unused random ID");
}
