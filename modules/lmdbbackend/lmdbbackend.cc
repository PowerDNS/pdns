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

#if 0
#define DEBUGLOG(msg) L<<Logger::Error<<msg
#else
#define DEBUGLOG(msg) do {} while(0)
#endif

LMDBBackend::LMDBBackend(const string &suffix)
{
    setArgPrefix("lmdb"+suffix);
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

    if( (rc = mdb_env_create(&env))  )
        throw PDNSException("Couldn't open LMDB database " + path + ": mdb_env_create() returned " + mdb_strerror(rc));

    if( (rc = mdb_env_set_maxdbs( env, 3 )) )
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

}

void LMDBBackend::close_db() {
    L<<Logger::Error<<"Closing LMDB database"<< endl;

    mdb_cursor_close(data_cursor);
    mdb_cursor_close(zone_cursor);
    mdb_cursor_close(data_extended_cursor);
    mdb_dbi_close(env, data_db);
    mdb_dbi_close(env, zone_db);
    mdb_dbi_close(env, data_extended_db);
    mdb_txn_abort(txn);
    mdb_env_close(env);
}

LMDBBackend::~LMDBBackend()
{
    close_db();
}

void LMDBBackend::reload() {
    close_db();
    open_db();
}

// Get the zone name and value of the requested zone (reversed) OR the entry
// just before where it should have been
bool LMDBBackend::getAuthZone( string &rev_zone )
{
    MDB_val key, data;
    // XXX can do this just using char *

    string orig = rev_zone;
    key.mv_data = (char *)rev_zone.c_str();
    key.mv_size = rev_zone.length();

    // Release our transaction and cursors in order to get latest data
    mdb_txn_reset( txn );
    mdb_txn_renew( txn );
    mdb_cursor_renew( txn, zone_cursor );
    mdb_cursor_renew( txn, data_cursor );
    mdb_cursor_renew( txn, data_extended_cursor );

    // Find the nearest record, or the last record if none
    if( mdb_cursor_get(zone_cursor, &key, &data, MDB_SET_RANGE) )
        mdb_cursor_get(zone_cursor, &key, &data, MDB_LAST);

    rev_zone.assign( (const char *)key.mv_data, key.mv_size );

    DEBUGLOG("Auth key: " << rev_zone <<endl);

    /* Only skip this bit if we got an exact hit on the SOA. otherwise we have
     * to go back to the previous record */
    if( orig.compare( rev_zone ) != 0 ) {
        /* Skip back 1 entry to what should be a substring of what was searched
         * for (or a totally different entry) */
        if( mdb_cursor_get(zone_cursor, &key, &data, MDB_PREV) ) {
            // At beginning of database; therefore didn't actually hit the
            // record. Return false
            return false;
        }

        rev_zone.assign( (const char *)key.mv_data, key.mv_size );
    }

    return true;
}

bool LMDBBackend::getAuthData( SOAData &soa, DNSPacket *p )
{
    MDB_val key, value;
    if( mdb_cursor_get(zone_cursor, &key, &value, MDB_GET_CURRENT) )
        return false;

    string data( (const char *)value.mv_data, value.mv_size );
    DEBUGLOG("Auth record data " << data<<endl);

// XXX do this in C too
    vector<string>parts;
    stringtok(parts,data,"\t");

    if(parts.size() != 3 )
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

    L<<Logger::Info<<" [LMDBBackend] This is the LMDBBackend version ("__DATE__", "__TIME__") reporting"<<endl;
  }
};

static LMDBLoader lmdbLoader;

