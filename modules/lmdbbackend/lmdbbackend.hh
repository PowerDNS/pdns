/*
 * LMDBBackend - a high performance LMDB based backend for PowerDNS written by
 * Mark Zealey, 2013
 */

#include <lmdb.h>
#include <pthread.h>
#include <pdns/dnsbackend.hh>

class LMDBBackend : public DNSReversedBackend
{
private:

    MDB_env *env;
    MDB_dbi data_db, zone_db, data_extended_db, rrsig_db, nsecx_db;
    MDB_txn *txn;
    MDB_cursor *data_cursor, *zone_cursor, *data_extended_cursor, *rrsig_cursor, *nsecx_cursor;

    // Domain that we are querying for in list()/lookup()/get(). In original case and direction.
    string d_origdomain;

    // Current QType being queried for
    QType d_curqtype;

    // Is this the first call to ::get() ?
    bool d_first;

    // Is dnssec enabled ?
    bool d_doDnssec;

    // Current domain ID being queried for
    int d_domain_id;

    // The reversed and lowercase key that we are querying in the database. Set after the first ::get() call.
    string d_querykey;

    // d_querykey with some additional bits potentially tacked on to make searching faster
    string d_searchkey;

    // d_lastreload last time the db was reloaded
    int d_lastreload;

    void open_db();
    void close_db();
    void needReload();
    inline bool get_finished();
    static int s_reloadcount;
    static pthread_rwlock_t s_initlock;

public:
    LMDBBackend(const string &suffix="");
    ~LMDBBackend();
    bool list(const string &target, int id, bool include_disabled=false);
    void lookup(const QType &type, const string &qdomain, DNSPacket *p, int zoneId);
    void reload();
    bool get(DNSResourceRecord &rr);

    bool getDomainMetadata(const string& name, const std::string& kind, std::vector<std::string>& meta);
    bool getDirectNSECx(uint32_t id, const string &hashed, const QType &qtype, string &before, DNSResourceRecord &rr);
    bool getDirectRRSIGs(const string &signer, const string &qname, const QType &qtype, vector<DNSResourceRecord> &rrsigs);

    bool getAuthZone( string &rev_zone );
    bool getAuthData( SOAData &, DNSPacket *);
};
