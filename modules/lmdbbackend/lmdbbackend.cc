/*
 * LMDBBackend - a high performance LMDB based backend for PowerDNS written by
 * Mark Zealey, 2013
 *
 * This was originally going to be a backend using BerkeleyDB 5 for high
 * performance DNS over massive (millions of zones) databases. However,
 * BerkeleyDB had a number of issues to do with locking, contention and
 * corruption which made it unsuitable for use. Instead, we use LMDB to perform
 * very fast lookups.
 *
 * See the documentation for more details, and lmdb-example.pl for an example
 * script which generates a simple zone.
 */

#include <pdns/utility.hh>
#include <pdns/dnsbackend.hh>
#include <pdns/dns.hh>
#include <pdns/dnspacket.hh>
#include <pdns/pdnsexception.hh>
#include <pdns/logger.hh>
#include <signal.h>
#include "lmdbbackend.hh"
#include <pdns/arguments.hh>
#include <pdns/base32.hh>
#include <pdns/lock.hh>

#if 0
#define DEBUGLOG(msg) L<<Logger::Error<<msg
#else
#define DEBUGLOG(msg) do {} while(0)
#endif

int LMDBBackend::s_reloadcount=0;
pthread_mutex_t LMDBBackend::s_initlock = PTHREAD_MUTEX_INITIALIZER;

LMDBBackend::LMDBBackend(const string &suffix)
{
    setArgPrefix("lmdb"+suffix);
    try {
      d_doDnssec = mustDo("experimental-dnssec");
    }
    catch (ArgException e) {
      d_doDnssec = false;
    }
    d_lastreload = s_reloadcount;
    open_db();
}

void LMDBBackend::open_db() {
    L<<Logger::Error<<"Loading LMDB database " << getArg("datapath") << endl;

    string path = getArg("datapath");
    int rc;
    int major, minor, patch;

    string verstring( mdb_version( &major, &minor, &patch ) );
    if( MDB_VERINT( major, minor, patch ) < MDB_VERINT( 0, 9, 8 ) )
        throw PDNSException( "LMDB Library version too old (" + verstring + "). Needs to be 0.9.8 or greater" );

    Lock l(&s_initlock);

    if( (rc = mdb_env_create(&env))  )
        throw PDNSException("Couldn't open LMDB database " + path + ": mdb_env_create() returned " + mdb_strerror(rc));

    if( (rc = mdb_env_set_maxdbs( env, d_doDnssec ? 5 : 3)) )
        throw PDNSException("Couldn't open LMDB database " + path + ": mdb_env_set_maxdbs() returned " + mdb_strerror(rc));

    if( (rc = mdb_env_open(env, path.c_str(), MDB_RDONLY, 0)) )
        throw PDNSException("Couldn't open LMDB database " + path + ": mdb_env_open() returned " + mdb_strerror(rc));

    if( (rc = mdb_txn_begin(env, NULL, MDB_RDONLY, &txn) ))
        throw PDNSException("Couldn't start LMDB txn " + path + ": mdb_txn_begin() returned " + mdb_strerror(rc));

    if( (rc = mdb_dbi_open(txn, "zone", 0, &zone_db) ) )
        throw PDNSException("Couldn't open LMDB zone database " + path + ": mdb_dbi_open() returned " + mdb_strerror(rc));
    if( (rc = mdb_cursor_open(txn, zone_db, &zone_cursor) ))
        throw PDNSException("Couldn't open cursor on LMDB zone database " + path + ": mdb_cursor_open() returned " + mdb_strerror(rc));

    if( (rc = mdb_dbi_open(txn, "data", MDB_DUPSORT, &data_db) ))
        throw PDNSException("Couldn't open LMDB data database " + path + ": mdb_dbi_open() returned " + mdb_strerror(rc));
    if( (rc = mdb_cursor_open(txn, data_db, &data_cursor) ))
        throw PDNSException("Couldn't open cursor on LMDB data database " + path + ": mdb_cursor_open() returned " + mdb_strerror(rc));

    if( (rc = mdb_dbi_open(txn, "extended_data", 0, &data_extended_db) ))
        throw PDNSException("Couldn't open LMDB extended_data database " + path + ": mdb_dbi_open() returned " + mdb_strerror(rc));
    if( ( rc = mdb_cursor_open(txn, data_extended_db, &data_extended_cursor)) )
        throw PDNSException("Couldn't open cursor on LMDB data_extended database " + path + ": mdb_cursor_open() returned " + mdb_strerror(rc));

    if(d_doDnssec) {
      DEBUGLOG("Experimental dnssec support enabled"<<endl);
      if( (rc = mdb_dbi_open(txn, "rrsig", MDB_DUPSORT, &rrsig_db) ))
          throw PDNSException("Couldn't open LMDB rrsig database " + path + ": mdb_dbi_open() returned " + mdb_strerror(rc));
      if( ( rc = mdb_cursor_open(txn, rrsig_db, &rrsig_cursor)) )
          throw PDNSException("Couldn't open cursor on LMDB rrsig database " + path + ": mdb_cursor_open() returned " + mdb_strerror(rc));

      if( (rc = mdb_dbi_open(txn, "nsecx", 0, &nsecx_db) ))
          throw PDNSException("Couldn't open LMDB nsecx database " + path + ": mdb_dbi_open() returned " + mdb_strerror(rc));
      if( ( rc = mdb_cursor_open(txn, nsecx_db, &nsecx_cursor)) )
          throw PDNSException("Couldn't open cursor on LMDB nsecx database " + path + ": mdb_cursor_open() returned " + mdb_strerror(rc));
    }
}

void LMDBBackend::close_db() {
    L<<Logger::Error<<"Closing LMDB database"<< endl;

    mdb_cursor_close(data_cursor);
    mdb_cursor_close(zone_cursor);
    mdb_cursor_close(data_extended_cursor);
    mdb_dbi_close(env, data_db);
    mdb_dbi_close(env, zone_db);
    mdb_dbi_close(env, data_extended_db);
    if (d_doDnssec) {
      mdb_cursor_close(rrsig_cursor);
      mdb_cursor_close(nsecx_cursor);
      mdb_dbi_close(env, rrsig_db);
      mdb_dbi_close(env, nsecx_db);
    }
    mdb_txn_abort(txn);
    mdb_env_close(env);
}

LMDBBackend::~LMDBBackend()
{
    close_db();
}

void LMDBBackend::reload() {
  ++s_reloadcount;
}

void LMDBBackend::needReload() {
  if (s_reloadcount > d_lastreload) {
    d_lastreload = s_reloadcount;
    close_db();
    open_db();
  }
}

bool LMDBBackend::getDomainMetadata(const string& name, const std::string& kind, std::vector<std::string>& meta)
{
  if (!d_doDnssec)
    return false;

  needReload();

  if (kind == "PRESIGNED" || kind == "NSEC3PARAM") {
    int rc;
    MDB_val key, data;
    string key_str, cur_value;
    vector<string> valparts;

    key_str=bitFlip(labelReverse(toLower(name)))+"\xff";
    key.mv_data = (char *)key_str.c_str();
    key.mv_size = key_str.length();

    if ((rc = mdb_cursor_get(zone_cursor, &key, &data, MDB_SET_KEY)) == 0) {
      cur_value.assign((const char *)data.mv_data, data.mv_size);
      stringtok(valparts,cur_value,"\t");

      if (valparts.size() == 4) {
        if (kind == "PRESIGNED")
          meta.push_back("1");
        else if (valparts[3] != "1")
          meta.push_back(valparts[3]);
      }
    }

    if (rc == MDB_NOTFOUND)
      DEBUGLOG("Metadata records for zone: '"<<name<<"'' not found. This is impossible !!!"<<endl);
  }

  return true;
}

bool LMDBBackend::getDirectNSECx(uint32_t id, const string &hashed, const QType &qtype, string &before, DNSResourceRecord &rr)
{
  if (!d_doDnssec)
    return false;

  needReload();

  MDB_val key, data;
  string key_str, cur_key, cur_value;
  vector<string> keyparts, valparts;

  if (qtype == QType::NSEC)
    key_str=itoa(id)+"\t"+bitFlip(hashed)+"\xff";
  else
    key_str=itoa(id)+"\t"+toBase32Hex(bitFlip(hashed));
  key.mv_data = (char *)key_str.c_str();
  key.mv_size = key_str.length();

  before.clear();
  if(!mdb_cursor_get(nsecx_cursor, &key, &data, MDB_SET_RANGE)) {
    cur_key.assign((const char *)key.mv_data, key.mv_size);
    cur_value.assign((const char *)data.mv_data, data.mv_size);
    stringtok(keyparts,cur_key,"\t");
    stringtok(valparts,cur_value,"\t");

    if( keyparts.size() != 2 || valparts.size() != 4 ) {
      throw PDNSException("Invalid record in nsecx table: key: '" + cur_key + "'; value: "+ cur_value);
    }

    // is the key a full match or does the id part match our zone?
    // if it does we have a valid answer.
    if (!key_str.compare(cur_key) || atoi(keyparts[0].c_str()) == (int) id) // FIXME we need atoui
      goto hasnsecx;
  }
  // no match, now we look for the last record in the NSECx chain.
  key_str=itoa(id)+"\t";
  key.mv_data = (char *)key_str.c_str();
  key.mv_size = key_str.length();

  if(!mdb_cursor_get(nsecx_cursor, &key, &data, MDB_NEXT_NODUP )) {
    cur_key.assign((const char *)key.mv_data, key.mv_size);
    cur_value.assign((const char *)data.mv_data, data.mv_size);
    stringtok(keyparts,cur_key,"\t");
    stringtok(valparts,cur_value,"\t");

    if( keyparts.size() != 2 || valparts.size() != 4 ) {
      throw PDNSException("Invalid record in nsecx table: key: '" + cur_key + "'; value: "+ cur_value);
    }

    if (!key_str.compare(cur_key) || atoi(keyparts[0].c_str()) == (int) id) // FIXME we need atoui
      goto hasnsecx;
  }

  DEBUGLOG("NSECx record for '"<<toBase32Hex(bitFlip(hashed))<<"'' in zone '"<<id<<"' not found"<<endl);
  return true;

hasnsecx:
  if (qtype == QType::NSEC)
    before=bitFlip(keyparts[1]).c_str();
  else
    before=bitFlip(fromBase32Hex(keyparts[1]));
  rr.qname=valparts[0];
  rr.ttl=atoi(valparts[1].c_str());
  rr.qtype=DNSRecordContent::TypeToNumber(valparts[2]);
  rr.content=valparts[3];
  rr.d_place=DNSResourceRecord::AUTHORITY;
  rr.domain_id=id;
  rr.auth=true;

  return true;
}

bool LMDBBackend::getDirectRRSIGs(const string &signer, const string &qname, const QType &qtype, vector<DNSResourceRecord> &rrsigs)
{
  if (!d_doDnssec)
    return false;

  needReload();

  int rc;
  MDB_val key, data;
  string key_str, cur_value;
  vector<string> valparts;

  key_str=signer+"\t"+makeRelative(qname, signer)+"\t"+qtype.getName();
  key.mv_data = (char *)key_str.c_str();
  key.mv_size = key_str.length();

  if ((rc = mdb_cursor_get(rrsig_cursor, &key, &data, MDB_SET_KEY)) == 0) {
    DNSResourceRecord rr;
    rr.qname=qname;
    rr.qtype=QType::RRSIG;
    //rr.d_place = (DNSResourceRecord::Place) signPlace;
    rr.auth=false;

    do {
      cur_value.assign((const char *)data.mv_data, data.mv_size);
      stringtok(valparts,cur_value,"\t");

      if( valparts.size() != 2 ) {
        throw PDNSException("Invalid record in rrsig table: qname: '" + qname + "'; value: "+ cur_value);
      }

      rr.ttl=atoi(valparts[0].c_str());
      rr.content = valparts[1];
      rrsigs.push_back(rr);

    } while (mdb_cursor_get(rrsig_cursor, &key, &data, MDB_NEXT_DUP) == 0);
  }

  if (rc == MDB_NOTFOUND)
    DEBUGLOG("RRSIG records for qname: '"<<qname<<"'' with type: '"<<qtype.getName()<<"' not found"<<endl);

  return true;
}

// Get the zone name of the requested zone (labelReversed) OR the name of the closest parrent zone
bool LMDBBackend::getAuthZone( string &rev_zone )
{
    needReload();

    MDB_val key, data;
    // XXX can do this just using char *

    string key_str=bitFlip(rev_zone+" ");
    key.mv_data = (char *)key_str.c_str();
    key.mv_size = key_str.length();

    // Release our transaction and cursors in order to get latest data
    mdb_txn_reset( txn );
    mdb_txn_renew( txn );
    mdb_cursor_renew( txn, zone_cursor );
    mdb_cursor_renew( txn, data_cursor );
    mdb_cursor_renew( txn, data_extended_cursor );
    if (d_doDnssec) {
      mdb_cursor_renew( txn, rrsig_cursor );
      mdb_cursor_renew( txn, nsecx_cursor );
    }

    // Find the best record
    if( mdb_cursor_get( zone_cursor, &key, &data, MDB_SET_RANGE ) == 0 && key.mv_size <= key_str.length() ) {
      // Found a shorter match. Now look if the zones are equal up to key-length-1. If they are check
      // if position key-length in key_str is a label separator. If all this is true we have a match.
      if( key_str.compare( 0, key.mv_size-1, (const char *) key.mv_data, key.mv_size-1  ) == 0 && key.mv_size && key_str[key.mv_size-1] == ~' ') {
        rev_zone.resize( key.mv_size-1 );

        DEBUGLOG("Auth key: " << rev_zone <<endl);

        return true;
      }
    }

    //reset the cursor the data in it is invallid
    mdb_cursor_renew( txn, zone_cursor );

    return false;
}

bool LMDBBackend::getAuthData( SOAData &soa, DNSPacket *p )
{
    needReload();

    MDB_val key, value;
    if( mdb_cursor_get(zone_cursor, &key, &value, MDB_GET_CURRENT) )
        return false;

    string data( (const char *)value.mv_data, value.mv_size );
    DEBUGLOG("Auth record data " << data<<endl);

// XXX do this in C too
    vector<string>parts;
    stringtok(parts,data,"\t");

    if(parts.size() < 3)
        throw PDNSException("Invalid record in zone table: " + data );

    fillSOAData( parts[2], soa );

    soa.domain_id = atoi( parts[0].c_str() );
    soa.ttl = atoi( parts[1].c_str() );

    soa.scopeMask = 0;
    soa.db = this;

    return true;
}

// Called to start an AXFR then ->get() is called. Return true if the domain exists
bool LMDBBackend::list(const string &target, int zoneId, bool include_disabled) {
    DEBUGLOG("list() requested for " <<target << endl);
    d_first = true;
    d_origdomain = target;
    d_domain_id = zoneId;
    d_curqtype = QType::AXFR;

    // getSOA will have been called first to ensure the domain exists so if
    // that's the case then there's no reason we can't AXFR it.

    return true;
}

void LMDBBackend::lookup(const QType &type, const string &inQdomain, DNSPacket *p, int zoneId)
{
    DEBUGLOG("lookup: " <<inQdomain << " " << type.getName() << endl);

    needReload();

    d_first = true;
    d_origdomain = inQdomain;
    d_curqtype = type;
}

inline bool LMDBBackend::get_finished()
{
    d_origdomain = "";

    return false;
}

bool LMDBBackend::get(DNSResourceRecord &rr)
{
    MDB_val key, value;
    bool is_axfr = (d_curqtype == QType::AXFR);
    bool is_full_key = ( ! is_axfr && d_curqtype != QType::ANY );

    DEBUGLOG("get : " <<d_origdomain<< endl);
    if( !d_origdomain.length() )
        return false;

    DEBUGLOG("Starting Q " << d_first<< endl);

    if( d_first ) {
        d_first = false;

        // Reverse the query string
        string lowerq = toLower( d_origdomain );
        d_querykey = string( lowerq.rbegin(), lowerq.rend() );
        d_searchkey = d_querykey;

        // For normal queries ensure that we are only trying to get the exact
        // record and also try to specify the type too to make negatives a lot
        // quicker
        if( ! is_axfr ) {
            d_searchkey += "\t";

            // Search by query type too to easily exclude anything that doesn't
            // belong to us
            if( is_full_key )
                d_searchkey += d_curqtype.getName();
        }

        key.mv_size = d_searchkey.length();
        key.mv_data = (char *)d_searchkey.c_str();
        if( mdb_cursor_get(data_cursor, &key, &value, is_full_key ? MDB_SET_KEY : MDB_SET_RANGE ) )
            return get_finished();
    } else {
next_record:
        key.mv_size = 0;
        if( mdb_cursor_get(data_cursor, &key, &value, is_full_key ? MDB_NEXT_DUP : MDB_NEXT ) )
            return get_finished();
    }

    // Some buggy versions of lmdb will do this. Should be caught in opendb above though.
    if( key.mv_size == 0 ) {
        DEBUGLOG("No key returned. Error" << endl);
        return get_finished();
    }

    string cur_value((const char *)value.mv_data, value.mv_size);
    string cur_key((const char *)key.mv_data, key.mv_size);

    DEBUGLOG("querykey: " << d_querykey << "; cur_key: " <<cur_key<< "; cur_value: " << cur_value << endl);

    vector<string> keyparts, valparts;

    stringtok(keyparts,cur_key,"\t");
    stringtok(valparts,cur_value,"\t");

    if( valparts.size() == 2 && valparts[0] == "REF" ) {
        MDB_val extended_key, extended_val;

        // XXX parse into an int and have extended table as MDB_INTEGER to have
        // a bit better performance/smaller space?
        extended_key.mv_data = (char *)valparts[1].c_str();
        extended_key.mv_size = valparts[1].length();

        if( int rc = mdb_cursor_get( data_extended_cursor, &extended_key, &extended_val, MDB_SET_KEY ) )
            throw PDNSException("Record " + cur_key + " references extended record " + cur_value + " but this doesn't exist: " + mdb_strerror( rc ));

        cur_value.assign((const char *)extended_val.mv_data, extended_val.mv_size);
        valparts.clear();
        stringtok(valparts, cur_value, "\t");
    }

    if( keyparts.size() != 2 || valparts.size() != 3 )
        throw PDNSException("Invalid record in record table: key: '" + cur_key + "'; value: "+ cur_value);

    string compare_string = cur_key.substr(0, d_searchkey.length());
    DEBUGLOG( "searchkey: " << d_searchkey << "; compare: " << compare_string << ";" << endl);

    // If we're onto records not beginning with this search prefix, then we
    // must be past the end
    if( compare_string.compare( d_searchkey ) )
        return get_finished();

    int domain_id = atoi( valparts[0].c_str() );

    // If we are doing an AXFR and the record fetched has been outside of our domain then end the transfer
    if( is_axfr ) {
        // Check it's not a subdomain ie belongs to this record
        if( domain_id != d_domain_id )
            goto next_record;

        // If it's under the main domain then append the . to the comparison to
        // ensure items outside our zone don't enter
        if( keyparts[0].length() > d_querykey.length() ) {
            string test = d_querykey;
            test.append(".");

            compare_string = cur_key.substr(0, d_querykey.length() + 1);

            DEBUGLOG("test: " << test << "; compare: " << compare_string << ";" << endl);

            if( test.compare( compare_string ) )
                goto next_record;
        }

        // We need to maintain query casing so strip off domain (less dot) and append originial query
        string sub = keyparts[0].substr( d_origdomain.length(), string::npos );
        rr.qname = string( sub.rbegin(), sub.rend() ) + d_origdomain;
    } else
        rr.qname = d_origdomain; // use cached and original casing

    DEBUGLOG("Found record: " <<cur_key << ": "<<valparts.size() << endl);

    DEBUGLOG("pass! " << rr.qname << ";" << endl);
    rr.qtype = keyparts[1];

    /* Filter records to only match query type */
    if( d_curqtype != QType::ANY && !is_axfr && rr.qtype != d_curqtype )
        goto next_record;

    DEBUGLOG("Correct record type" << endl);
    rr.auth = 1;

    rr.domain_id = domain_id;
    rr.ttl = atoi( valparts[1].c_str() );

    if( rr.qtype.getCode() != QType::MX && rr.qtype.getCode() != QType::SRV )
        rr.content = valparts[2];
    else {
        // split out priority field
        string::size_type pos = valparts[2].find_first_of(" ", 0);

        rr.priority = atoi( valparts[2].substr(0, pos).c_str() );
        rr.content = valparts[2].substr(pos+1, valparts[2].length());
    }

    return true;
}

class LMDBFactory : public BackendFactory
{
public:
  LMDBFactory() : BackendFactory("lmdb") {}
  void declareArguments(const string &suffix="")
  {
    declare(suffix,"datapath","Path to the directory containing the lmdb files","/etc/pdns/data");
    declare(suffix,"experimental-dnssec","Enable experimental DNSSEC processing","no");
  }
  DNSBackend *make(const string &suffix="")
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
    BackendMakers().report(new LMDBFactory);
    L << Logger::Info << "[lmdbbackend] This is the lmdb backend version " VERSION " reporting" << endl;
  }
};

static LMDBLoader lmdbLoader;

