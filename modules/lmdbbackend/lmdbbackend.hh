/*
 * LMDBBackend - a high performance LMDB based backend for PowerDNS written by
 * Mark Zealey, 2013
 */

#include <lmdb.h>
#include <pdns/dnsbackend.hh>

class LMDBBackend : public DNSReversedBackend
{
private:

    MDB_env *env;
    MDB_dbi data_db, zone_db, data_extended_db;
    MDB_txn *txn;
    MDB_cursor *data_cursor, *zone_cursor, *data_extended_cursor;

    // Domain that we are querying for in list()/lookup()/get(). In original case and direction.
    string d_origdomain;

    // Current QType being queried for
    QType d_curqtype;

    // Is this the first call to ::get() ?
    bool d_first;

    // Current domain ID being queried for
    int d_domain_id;

    // The reversed and lowercase key that we are querying in the database. Set after the first ::get() call.
    string d_querykey;

    // d_querykey with some additional bits potentially tacked on to make searching faster
    string d_searchkey;

    void open_db();
    void close_db();
    inline bool get_finished();

public:
    LMDBBackend(const string &suffix="");
    ~LMDBBackend();
    bool list(const string &target, int id);
    void lookup(const QType &type, const string &qdomain, DNSPacket *p, int zoneId);
    void reload();
    bool get(DNSResourceRecord &rr);

    bool getAuthZone( string &rev_zone );
    bool getAuthData( SOAData &, DNSPacket *);
};
