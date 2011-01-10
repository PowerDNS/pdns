/*        geobackend.cc
 *         Copyright (C) 2004 Mark Bergsma <mark@nedworks.org>
 *        	This software is licensed under the terms of the GPL, version 2.
 * 
 *         $Id$
 */

#include <fstream>
#include <sstream>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <dirent.h>

#include <pdns/misc.hh>
#include <pdns/lock.hh>
#include <pdns/dnspacket.hh>
#include <boost/algorithm/string.hpp>
#include "geobackend.hh"

using boost::trim_right;

// Static members

IPPrefTree * GeoBackend::ipt;
vector<string> GeoBackend::nsRecords;
map<string, GeoRecord*> GeoBackend::georecords;
string GeoBackend::soaMasterServer;
string GeoBackend::soaHostmaster;
string GeoBackend::zoneName;
uint32_t GeoBackend::geoTTL;
uint32_t GeoBackend::nsTTL;
time_t GeoBackend::lastDiscoverTime = 0;
const string GeoBackend::logprefix = "[geobackend] ";
bool GeoBackend::first = true;
int GeoBackend::backendcount = 0;
pthread_mutex_t GeoBackend::startup_lock;
pthread_mutex_t GeoBackend::ipt_lock;

// Class GeoRecord

GeoRecord::GeoRecord() : origin(".") {}

// Class GeoBackend, public methods

GeoBackend::GeoBackend(const string &suffix) : forceReload(false) {
        setArgPrefix("geo" + suffix);
        
        // Make sure only one (the first) backend instance is initializing static things
        Lock lock(&startup_lock);

        backendcount++;

        if (!first)
        	return;
        first = false;
        
        ipt = NULL;
        
        loadZoneName();
        loadTTLValues();
        loadSOAValues();
        loadNSRecords();
        reload();
}

GeoBackend::~GeoBackend() {
        Lock lock(&startup_lock);
        backendcount--;	
        if (backendcount == 0) {
        	for (map<string, GeoRecord*>::iterator i = georecords.begin(); i != georecords.end(); ++i)
        		delete i->second;
        	
        	if (ipt != NULL) {
        		delete ipt;
        		ipt = NULL;
        	}
        }
}

bool GeoBackend::getSOA(const string &name, SOAData &soadata, DNSPacket *p) {
        if (toLower(name) != toLower(zoneName) || soaMasterServer.empty() || soaHostmaster.empty())
        	return false;
        
        soadata.nameserver = soaMasterServer;
        soadata.hostmaster = soaHostmaster;
        soadata.domain_id = 1;	// We serve only one zone
        soadata.db = this;
        
        // These values are bogus for backends like this one
        soadata.serial = 1;
        soadata.refresh = 86400;
        soadata.retry = 2*soadata.refresh;
        soadata.expire = 7*soadata.refresh;
        soadata.default_ttl = 3600;	
        
        return true;
}

void GeoBackend::lookup(const QType &qtype, const string &qdomain, DNSPacket *pkt_p, int zoneId) {
        answers.clear();
        
        if ((qtype.getCode() == QType::NS || qtype.getCode() == QType::ANY)
        	&& toLower(qdomain) == toLower(zoneName))
        	queueNSRecords(qdomain);
        
        if (qtype.getCode() == QType::ANY || qtype.getCode() == QType::CNAME)
        	answerGeoRecord(qtype, qdomain, pkt_p);
        
        if ((qtype.getCode() == QType::ANY || qtype.getCode() == QType::A)
        	&& toLower(qdomain) == "localhost." + toLower(zoneName))
        	answerLocalhostRecord(qdomain, pkt_p);
        
        if (!answers.empty())	
        	i_answers = answers.begin();		
}

bool GeoBackend::list(const string &target, int domain_id) {
        answers.clear();
        queueNSRecords(zoneName);
        answerLocalhostRecord("localhost."+zoneName, NULL);
        queueGeoRecords();
        
        if (!answers.empty())
        	i_answers = answers.begin();
        return true;
}

bool GeoBackend::get(DNSResourceRecord &r) {
        if (answers.empty()) return false;
        
        if (i_answers != answers.end()) {
        	// FIXME DNSResourceRecord could do with a copy constructor
        	DNSResourceRecord *ir = *i_answers;
        	r.qtype = ir->qtype;
        	r.qname = ir->qname;
        	r.content = ir->content;
        	r.priority = ir->priority;
        	r.ttl = ir->ttl;
        	r.domain_id = ir->domain_id;
        	r.last_modified = ir->last_modified;
          r.auth = 1;
        			
        	delete ir;
        	i_answers++;
        	return true;
        }
        else {
        	answers.clear();
        	return false;
        }
}

void GeoBackend::reload() {
        forceReload = true;
        rediscover();
        forceReload = false;
}

void GeoBackend::rediscover(string *status) {
        // Store current time for use after discovery
        struct timeval nowtime;
        gettimeofday(&nowtime, NULL);
        
        loadIPLocationMap();
        loadGeoRecords();
        
        // Use time at start of discovery for checking whether files have changed
        // next time
        lastDiscoverTime = nowtime.tv_sec;
}

// Private methods

void GeoBackend::answerGeoRecord(const QType &qtype, const string &qdomain, DNSPacket *p) {        	
        const string lqdomain = toLower(qdomain);

        if (georecords.count(lqdomain) == 0) 
        	return;
        
        GeoRecord *gr = georecords[lqdomain];
        				
        // Try to find the isocode of the country corresponding to the source ip
        // If that fails, use the default
        short isocode = 0;
        if (p != NULL && ipt != NULL) {
        	try {
        		isocode = ipt->lookup(p->getRemote());
        	}
        	catch(ParsePrefixException &e) {	// Ignore
        		L << Logger::Notice << logprefix << "Unable to parse IP '"
        			<< p->getRemote()	<< " as IPv4 prefix" << endl;
        	}
        }
        
        DNSResourceRecord *rr = new DNSResourceRecord;
        string target = resolveTarget(*gr, isocode);
        fillGeoResourceRecord(qdomain, target, rr);
        
        L << Logger::Debug << logprefix << "Serving " << qdomain << " "
        	<< rr->qtype.getName() << " " << target << " to " << p->getRemote()
        	<< " (" << isocode << ")" << endl;
        	
        answers.push_back(rr);		
}

void GeoBackend::answerLocalhostRecord(const string &qdomain, DNSPacket *p) {
        short isocode = 0;
        if (p != NULL) {
        	try {
        		isocode = ipt->lookup(p->getRemote());
        	}
        	catch(ParsePrefixException &e) {}	// Ignore
        }
        
        ostringstream target;
        target << "127.0." << ((isocode >> 8) & 0xff) << "." << (isocode & 0xff);
        
        DNSResourceRecord *rr = new DNSResourceRecord;
        rr->qtype = QType::A;
        rr->qname = qdomain;
        rr->content = target.str();
        rr->priority = 0;
        rr->ttl = geoTTL;
        rr->domain_id = 1;
        rr->last_modified = 0;
        
        answers.push_back(rr);	
}

void GeoBackend::queueNSRecords(const string &qname) {
        // nsRecords may be empty, e.g. when used in overlay mode
        
        for (vector<string>::const_iterator i = nsRecords.begin(); i != nsRecords.end(); ++i) {
        	DNSResourceRecord *rr = new DNSResourceRecord;
        	rr->qtype = QType::NS;
        	rr->qname = qname;
        	rr->content = *i;
        	rr->priority = 0;
        	rr->ttl = nsTTL;
        	rr->domain_id = 1;
        	rr->last_modified = 0;
        	
        	answers.push_back(rr);
        }	
}

void GeoBackend::queueGeoRecords() {
        for (map<string, GeoRecord*>::const_iterator i = georecords.begin(); i != georecords.end(); ++i) {
        	GeoRecord *gr = i->second;
        	DNSResourceRecord *rr = new DNSResourceRecord;
        	
        	fillGeoResourceRecord(gr->qname, resolveTarget(*gr, 0), rr);
        	answers.push_back(rr);
        }
}

void GeoBackend::fillGeoResourceRecord(const string &qdomain, const string &target, DNSResourceRecord *rr) {
        rr->qtype = QType::CNAME;
        rr->qname = qdomain;
        rr->content = target;
        rr->priority = 0;
        rr->ttl = geoTTL;
        rr->domain_id = 1;
        rr->last_modified = 0;
}

const string GeoBackend::resolveTarget(const GeoRecord &gr, short isocode) const {
        // If no mapping exists for this isocode, use the default
        if (gr.dirmap.count(isocode) == 0)
        	isocode = 0;
        
        // Append $ORIGIN only if target does not end with a dot		
        string target(gr.dirmap.find(isocode)->second);
        if (target[target.size()-1] != '.')
        	target += gr.origin;
        else
        	target.resize(target.size()-1);
        	
        return target;
}

void GeoBackend::loadZoneName() {
        zoneName = getArg("zone");
        if (zoneName.empty())
        	throw AhuException("zone parameter must be set");	
}

void GeoBackend::loadTTLValues() {
        geoTTL = getArgAsNum("ttl");
        nsTTL = getArgAsNum("ns-ttl");
}

void GeoBackend::loadSOAValues() {
        vector<string> values;
        stringtok(values, getArg("soa-values"), " ,");
        
        if (values.empty())
        	// No SOA values, probably no SOA record wanted because of overlay mode
        	return;
        
        if (values.size() != 2)
        	throw AhuException("Invalid number of soa-values specified in configuration");
        
        soaMasterServer = values[0];
        soaHostmaster = values[1];	
}

void GeoBackend::loadNSRecords() {
        stringtok(nsRecords, getArg("ns-records"), " ,");
}

void GeoBackend::loadIPLocationMap() {
        string filename = getArg("ip-map-zonefile");
        
        if (filename.empty())
        	throw AhuException("No IP map zonefile specified in configuration");
        
        // Stat file to see if it has changed since last read
        struct stat stbuf;
        if (stat(filename.c_str(), &stbuf) != 0 || !S_ISREG(stbuf.st_mode)) {
        	const string errormsg = "stat() failed, or " + filename + " is no regular file.";
        	if (lastDiscoverTime == 0)	// We have no older map, bail out
        		throw AhuException(errormsg);
        	else {
        		// Log, but continue
        		L << Logger::Error << logprefix << errormsg;
        		return;
        	}
        }
        
        if (stbuf.st_mtime < lastDiscoverTime && !forceReload)	// File hasn't changed
        	return;
        
        ifstream ifs(filename.c_str(), ios::in);
        if (!ifs)
        	throw AhuException("Unable to open IP map zonefile for read: " + stringerror());
        	
        L << Logger::Info << logprefix << "Parsing IP map zonefile" << endl;
        
        IPPrefTree *new_ipt = new IPPrefTree;
        string line;
        int linenr = 0, entries = 0;
        
        while (getline(ifs, line)) {
        	linenr++;		
        	trim_right(line);	// Erase whitespace
        	
        	if (line[0] == '#')
        		continue;	// Skip comments

        	vector<string> words;
        	stringtok(words, line, " :");
        	
        	if (words.empty() || words[0] == "$SOA")
        		continue;
        		
        	// Assume words[0] is a prefix. Feed it to the ip prefix tree
        	try {
        		// Parse country code nr
        		if (words.size() < 2 || words[1].empty()) {
        			L << Logger::Warning << logprefix
        				<< "Country code number is missing at line " << linenr << endl;
        			continue;
        		}
        		
        		struct in_addr addr;
        		if (inet_aton(words[1].c_str(), &addr) < 0) {
        			L << Logger::Warning << logprefix << "Invalid IP address '"
        				<< words[1] << " at line " << linenr << endl;
        			continue;
        		}
        		short value = ntohl(addr.s_addr) & 0x7fff;
        		
        		new_ipt->add(words[0], value);
        		entries++;
        	}
        	catch(ParsePrefixException &e) {
        		L << Logger::Warning << logprefix << "Error while parsing prefix at line "
        			<< linenr << ": " << e.reason << endl;
        	}
        }
        ifs.close();
        
        L << Logger::Info << logprefix << "Finished parsing IP map zonefile: added " 
        	<< entries << " prefixes, stored in " << new_ipt->getNodeCount()
        	<< " nodes using " << new_ipt->getMemoryUsage() << " bytes of memory"
        	<< endl;
        
        // Swap the new tree with the old tree
        IPPrefTree *oldipt = NULL;
        {
        	Lock iptl(&ipt_lock);
        	
        	oldipt = ipt;
        	ipt = new_ipt;
        }
        
        // Delete the old ip prefix tree
        if (oldipt != NULL)
        	delete oldipt;
}

void GeoBackend::loadGeoRecords() {
        vector<GeoRecord*> newgrs;
        	
        vector<string> maps;
        stringtok(maps, getArg("maps"), " ,");
        for (vector<string>::const_iterator i = maps.begin(); i != maps.end(); ++i) {
        	struct stat stbuf;
        	
        	if (stat(i->c_str(), &stbuf) != 0)
        		continue;
        	
        	if (S_ISREG(stbuf.st_mode)) {
        		// Regular file
        		GeoRecord *gr = new GeoRecord;
        		gr->directorfile = *i;
        		newgrs.push_back(gr);
        	}
        	else if (S_ISDIR(stbuf.st_mode)) {	// Directory
        		DIR *dir = opendir(i->c_str());
        		if (dir != NULL) {
        			struct dirent *dent;
        			while ((dent = readdir(dir)) != NULL) {
        				string filename(*i);
        				if (filename[filename.size()-1] != '/')
        					filename += '/';
        				
        				if (dent->d_name[0] == '.')
        					continue;	// skip filenames starting with a dot
        					
        				filename += dent->d_name;
        				
        				if (stat(filename.c_str(), &stbuf) != 0 || !S_ISREG(stbuf.st_mode))
        					continue;	// skip everything but regular files
        					
        				GeoRecord *gr = new GeoRecord;
        				gr->directorfile = filename;
        				newgrs.push_back(gr);
        			}
        			closedir(dir);
        		}	
        	}
        }
        
        loadDirectorMaps(newgrs);
}

void GeoBackend::loadDirectorMaps(const vector<GeoRecord*> &newgrs) {
        map<string, GeoRecord*> new_georecords;
        
        int mapcount = 0;
        for (vector<GeoRecord*>::const_iterator i = newgrs.begin(); i != newgrs.end(); ++i) {
        	GeoRecord *gr = *i;
        	try {
        		loadDirectorMap(*gr);
        		if (new_georecords.count(gr->qname) == 0) {
        			new_georecords[gr->qname] = gr;
        			mapcount++;
        		}
        		else
        			throw AhuException("duplicate georecord " + gr->qname + ", skipping");
        	}
        	catch(AhuException &e) {
        		L << Logger::Error << logprefix << "Error occured while reading director file "
        			<< gr->directorfile << ": " << e.reason << endl;
        		delete gr;
        	}
        }
        
        // Swap the new georecord map with the old one.
        georecords.swap(new_georecords);
        	
        L << Logger::Notice << logprefix << "Finished parsing " << mapcount 
        	<< " director map files, "	<< newgrs.size() - mapcount << " failures" << endl;

        // Cleanup old georecords
        for (map<string, GeoRecord*>::iterator i = new_georecords.begin(); i != new_georecords.end(); ++i)
        	delete i->second;
}

void GeoBackend::loadDirectorMap(GeoRecord &gr) {
        L << Logger::Info << logprefix << "Parsing director map " << gr.directorfile << endl;
        
        ifstream ifs(gr.directorfile.c_str(), ios::in);
        if (!ifs)
        	throw AhuException("Error opening file.");
        
        string line;
        while(getline(ifs, line)) {
        	trim_right(line);	// Erase whitespace

        	if (line.empty() || line[0] == '#')
        		continue;	// Skip empty lines and comments
        
        	// Parse $RECORD
        	if (line.substr(0, 7) == "$RECORD") {
        		gr.qname = line.substr(8);
        		trim_right(gr.qname);
        		if (gr.qname[gr.qname.size()-1] != '.')
        			gr.qname += '.' + zoneName;
        		else {
        			gr.qname.resize(gr.qname.size()-1);
        			// Check whether zoneName is a prefix of this FQDN
        			if (gr.qname.rfind(zoneName) == string::npos)
        				throw AhuException("georecord " + gr.qname + " is out of zone " + zoneName);
        		}
        		continue;
        	}
        
        	// Parse $ORIGIN
        	if (line.substr(0, 7) == "$ORIGIN") {
        		gr.origin = line.substr(8);
        		trim_right_if(gr.origin, boost::is_any_of(" \t."));
        		gr.origin.insert(0, ".");
        		continue;
        	}	
        	
        	istringstream ii(line);
        	short isocode;
        	string target;
        	ii >> isocode >> target;
        	
        	gr.dirmap[isocode] = target;
        }
        
        // Do some checks on the validness of this director map / georecord
        
        if (gr.qname.empty())
        	throw AhuException("$RECORD line empty or missing, georecord qname unknown");
        
        if (gr.dirmap.count(0) == 0)
        	throw AhuException("No default (0) director map entry");
}
