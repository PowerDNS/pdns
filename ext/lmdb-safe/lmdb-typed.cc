#include "lmdb-typed.hh"
#include "pdns/dns_random.hh"

unsigned int MDBGetMaxID(MDBRWTransaction& txn, MDBDbi& dbi)
{
  auto cursor = txn->getRWCursor(dbi);
  MDBOutVal maxidval, maxcontent;
  unsigned int maxid{0};
  if(!cursor.get(maxidval, maxcontent, MDB_LAST)) {
    maxid = maxidval.get<unsigned int>();
  }
  return maxid;
}

unsigned int MDBGetRandomID(MDBRWTransaction& txn, MDBDbi& dbi)
{
  auto cursor = txn->getRWCursor(dbi);
  unsigned int id;
  for(int attempts=0; attempts<20; attempts++) {
    MDBOutVal key, content;

    // dns_random generates a random number in [0..signed_int_max-1]. We add 1 to avoid 0 and allow type_max.
    // 0 is avoided because the put() interface uses it to mean "please allocate a number for me"
    id = dns_random(std::numeric_limits<signed int>::max()) + 1;
    if(cursor.find(MDBInVal(id), key, content)) {
      return id;
    }
  }
  throw std::runtime_error("MDBGetRandomID() could not assign an unused random ID");
}


