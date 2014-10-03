/*        geobackend.hh
 *        	Copyright (C) 2004 Mark Bergsma <mark@nedworks.org>
 *        	This software is licensed under the terms of the GPL, version 2.
 * 
 *        	$Id$
 */


#include <vector>
#include <map>
#include <pthread.h>

#include <pdns/dnsbackend.hh>
#include <pdns/logger.hh>

#include "ippreftree.hh"

#include "pdns/namespaces.hh"

class GeoRecord {
public:
        GeoRecord();

        string qname;
        string origin;
        string directorfile;
        map<short, string> dirmap;
};

class GeoBackend : public DNSBackend{
public:

        GeoBackend(const string &suffix);
        ~GeoBackend();
        
        virtual void lookup(const QType &qtype, const string &qdomain, DNSPacket *pkt_p=0, int zoneId=-1);
        virtual bool list(const string &target, int domain_id, bool include_disabled=false);
        virtual bool get(DNSResourceRecord &r);
        virtual bool getSOA(const string &name, SOAData &soadata, DNSPacket *p=0);
        
        virtual void reload();
        virtual void rediscover(string *status = 0);
        
private:
        // Static resources, shared by all instances
        static IPPrefTree *ipt;
        static vector<string> nsRecords;
        static map<string, GeoRecord*> georecords;
        static string soaMasterServer;
        static string soaHostmaster;
        static string zoneName;
        static uint32_t geoTTL;
        static uint32_t nsTTL;
        static time_t lastDiscoverTime;
        const static string logprefix;
        
        bool forceReload;
        
        // Locking
        static bool first;
        static int backendcount;
        static pthread_mutex_t startup_lock;
        static pthread_mutex_t ipt_lock;

        vector<DNSResourceRecord*> answers;
        vector<DNSResourceRecord*>::const_iterator i_answers;
        
        void answerGeoRecord(const QType &qtype, const string &qdomain, DNSPacket *p);
        void answerLocalhostRecord(const string &qdomain, DNSPacket *p);
        void queueNSRecords(const string &qname);
        void queueGeoRecords();
        void fillGeoResourceRecord(const string &qname, const string &target, DNSResourceRecord *rr);
        const inline string resolveTarget(const GeoRecord &gr, short isocode) const;

        void loadZoneName();
        void loadTTLValues();
        void loadSOAValues();
        void loadNSRecords();
        void loadIPLocationMap();
        void loadGeoRecords();
        void loadDirectorMaps(const vector<GeoRecord*> &newgrs);
        void loadDirectorMap(GeoRecord &gr);
};

class GeoFactory : public BackendFactory{
public:
        GeoFactory() : BackendFactory("geo") {}
        
        void declareArguments(const string &suffix = "") {
        	declare(suffix, "zone", "zonename to be served", "");
        	declare(suffix, "soa-values", "values of the SOA master nameserver and hostmaster fields, comma separated", "");
        	declare(suffix, "ns-records", "targets of the NS records, comma separated.", "");
        	declare(suffix, "ttl", "TTL value for geo records", "3600");
        	declare(suffix, "ns-ttl", "TTL value for NS records", "86400");
        	declare(suffix, "ip-map-zonefile", "path to the rbldnsd format zonefile", "zz.countries.nerd.dk.rbldnsd");
        	declare(suffix, "maps", "list of paths to director maps or directories containing director map files", "");
        }
        
        DNSBackend *make(const string &suffix) {
        	return new GeoBackend(suffix);
        }
};

class GeoLoader {
public:
        GeoLoader() {
        	BackendMakers().report(new GeoFactory);
		L << Logger::Info << "[geobackend] This is the geo backend version " VERSION " reporting" << endl;
        }
};

static GeoLoader geoloader;
