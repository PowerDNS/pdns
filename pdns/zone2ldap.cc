/*
 *  PowerDNS BIND Zone to LDAP converter
 *  Copyright (C) 2003  Norbert Sendetzky
 *  Copyright (C) 2007  bert hubert
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  the Free Software Foundation
 *
 *  Additionally, the license of this program contains a special
 *  exception which allows to distribute the program in binary form when
 *  it is linked against OpenSSL.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <map>
#include <string>
#include <iostream>
#include <sstream>
#include <stdio.h>
#include "arguments.hh"
#include "bindparserclasses.hh"
#include "statbag.hh"
#include <boost/function.hpp>
#include "dnsrecords.hh"
#include "misc.hh"
#include "dns.hh"
#include "zoneparser-tng.hh"

using std::map;
using std::string;
using std::vector;

StatBag S;
ArgvMap args;
bool g_dnsttl;
bool g_pdnsinfo;
unsigned int g_domainid;
string g_basedn;
string g_metadatadn;
DNSName g_zonename;
map<DNSName,bool> g_objects;
map<string, bool> g_entries;
map<DNSName,bool> g_recorddata;
map<DNSName, map<string, bool> > g_recordttl;

static std::string encode_non_ascii( const std::string &input ) {
        std::ostringstream out;

        for ( auto i : input ) {
                if ( (unsigned char)i > 0x7F )
                        out << '\\' << int( (unsigned char)i );
                else
                        out << i;
        }

        return out.str();
}

static void callback_simple( unsigned int domain_id, const DNSName &domain, const string &qtype, const string &content, int ttl )
{
        DNSName host;

        if( ! domain.isPartOf(g_zonename) )
        {
                cerr << "Domain '" << domain << "'' not part of '" << g_zonename << "'"<< endl;
                return;
        }

        host = domain.makeRelative(g_zonename);

        if( g_pdnsinfo && qtype == "SOA" ) {
                cout << "dn: ou=" << domain << "," << g_metadatadn << endl;
                cout << "changetype: add" << endl;
                cout << "objectclass: organizationalUnit" << endl;
                cout << "ou: " << domain.toStringNoDot() << endl;
                cout << endl;
        }

        std::string stripped=stripDot(content);
        std::string rrvalue = stripped + ((stripped.empty() || stripped[stripped.size()-1]==' ') ? "." : "");
        std::string dn = "dc=";
        if( host.countLabels() ) { dn += host.toStringNoDot() + ",dc="; }
        dn += g_zonename.toStringNoDot() + "," + g_basedn;
        cout << "dn: " << dn << endl;

        if( host.countLabels() == 0 ) { host = g_zonename; }

        if( !g_entries[dn] )
        {
                g_entries[dn] = true;
                g_recorddata[domain] = true;

                cout << "changetype: add" << endl;
                cout << "objectclass: dnsdomain2" << endl;
                cout << "objectclass: domainrelatedobject" << endl;
                cout << "objectclass: PdnsRecordData" << endl;
                if( g_pdnsinfo && qtype == "SOA" ) {
                        cout << "objectclass: PdnsDomain" << endl;
                        cout << "PdnsDomainId: " << domain_id << endl;
                }
                cout << "dc: " << host.toStringNoDot() << endl;
                if( g_dnsttl ) { cout << "dnsttl: " << ttl << endl; }
                cout << "associateddomain: " << domain.toStringNoDot() << endl;
        }
        else
        {
                cout << "changetype: modify" << endl;
                if ( !g_recorddata[domain] ) {
                        g_recorddata[domain] = true;
                        cout << "add: objectClass" << endl;
                        cout << "objectClass: PdnsRecordData" << endl;
                        cout << "-" << endl;
                }
                if ( !g_recordttl.count( domain ) || !g_recordttl[domain].count( qtype ) ) {
                        g_recordttl[domain][qtype] = true;
                        cout << "add: PdnsRecordTTL" << endl;
                        cout << "PdnsRecordTTL: " << qtype << "|" << ttl << endl;
                        cout << "-" << endl;
                }
                cout << "add: " << qtype << "Record" << endl;
        }
        cout << qtype << "Record: " << rrvalue << endl << endl;
}



static void callback_tree( unsigned int domain_id, const DNSName &domain, const string &qtype, const string &content, int ttl )
{
        unsigned int i;
        string dn;
        DNSName net;
        vector<string> parts;

        stringtok( parts, domain.toStringNoDot(), "." );
        if( parts.empty() ) { return; }

        for( i = parts.size() - 1; i > 0; i-- )
        {
                net.prependRawLabel(parts[i]);
                dn = "dc=" + parts[i] + "," + dn;

                if( !g_objects[net] )
                {
                        g_objects[net] = true;

                        cout << "dn: " << dn << g_basedn << endl;
                        cout << "changetype: add" << endl;
                        cout << "objectclass: dnsdomain2" << endl;
                        cout << "objectclass: domainrelatedobject" << endl;
                        cout << "dc: " << parts[i] << endl;
                        cout << "associateddomain: " << net.toStringNoDot() << endl << endl;
                }

        }

        if( g_pdnsinfo && qtype == "SOA" ) {
                cout << "dn: ou=" << domain << "," << g_metadatadn << endl;
                cout << "changetype: add" << endl;
                cout << "objectclass: organizationalUnit" << endl;
                cout << "ou: " << domain.toStringNoDot() << endl;
                cout << endl;
        }

        std::string stripped=stripDot(content);
        std::string rrvalue = stripped + ((stripped.empty() || stripped[stripped.size()-1]==' ') ? "." : "");
        cout << "dn: " << "dc=" << parts[0] << "," << dn << g_basedn << endl;

        if( !g_objects[domain] )
        {
                g_objects[domain] = true;
                g_recorddata[domain] = true;

                cout << "changetype: add" << endl;
                cout << "objectclass: dnsdomain2" << endl;
                cout << "objectclass: domainrelatedobject" << endl;
                cout << "objectclass: PdnsRecordData" << endl;
                if( g_pdnsinfo && qtype == "SOA" ) {
                        cout << "objectclass: PdnsDomain" << endl;
                        cout << "PdnsDomainId: " << domain_id << endl;
                }
                cout << "dc: " << parts[0] << endl;
                if( g_dnsttl ) { cout << "dnsttl: " << ttl << endl; }
                cout << "associateddomain: " << domain.toStringNoDot() << endl;
        }
        else
        {
                cout << "changetype: modify" << endl;
                if( g_pdnsinfo && qtype == "SOA" ) {
                        cout << "add: objectclass" << endl;
                        cout << "objectclass: PdnsDomain" << endl;
                        cout << "-" << endl;
                        cout << "add: PdnsDomainId" << endl;
                        cout << "PdnsDomainId: " << domain_id << endl;
                        cout << "-" << endl;
                }
                if ( !g_recorddata[domain] ) {
                        g_recorddata[domain] = true;
                        cout << "add: objectClass" << endl;
                        cout << "objectClass: PdnsRecordData" << endl;
                        cout << "-" << endl;
                }
                if ( !g_recordttl.count( domain ) || !g_recordttl[domain].count( qtype ) ) {
                        g_recordttl[domain][qtype] = true;
                        cout << "add: PdnsRecordTTL" << endl;
                        cout << "PdnsRecordTTL: " << qtype << "|" << ttl << endl;
                        cout << "-" << endl;
                }
                cout << "add: " << qtype << "Record" << endl;
        }
        cout << qtype << "Record: " << rrvalue << endl << endl;
}



int main( int argc, char* argv[] )
{
        BindParser BP;
        vector<string> parts;


        try
        {
                std::ios_base::sync_with_stdio( false );
                reportAllTypes();
                args.setCmd( "help", "Provide a helpful message" );
                args.setCmd( "version", "Print the version" );
                args.setSwitch( "verbose", "Verbose comments on operation" ) = "no";
                args.setSwitch( "resume", "Continue after errors" ) = "no";
                args.setSwitch( "dnsttl", "Add dnsttl attribute to every entry" ) = "no";
                args.setSwitch( "pdns-info", "Add the PDNS domain info attributes (this mandates setting --metadata-dn)" ) = "no";
                args.set( "named-conf", "Bind 8 named.conf to parse" ) = "";
                args.set( "zone-file", "Zone file to parse" ) = "";
                args.set( "zone-name", "Specify a zone name if zone is set" ) = "";
                args.set( "basedn", "Base DN to store objects below" ) = "ou=hosts,o=mycompany,c=de";
                args.set( "layout", "How to arrange entries in the directory (simple or as tree)" ) = "simple";
                args.set( "domainid", "Domain ID of the first domain found (incremented afterwards)" ) = "1";
                args.set( "metadata-dn", "DN under which to store the domain metadata" ) = "";
                args.set( "max-generate-steps", "Maximum number of $GENERATE steps when loading a zone from a file")="0";

                args.parse( argc, argv );

                if(args.mustDo("version")) {
                  cerr<<"zone2ldap "<<VERSION<<endl;
                  exit(0);
                }

                if( args.mustDo( "help" ) )
                {
                        cout << "Syntax:" << endl << endl;
                        cout << args.helpstring() << endl;
                        exit( 0 );
                }

                if( argc < 2 )
                {
                        cerr << "Syntax:" << endl << endl;
                        cerr << args.helpstring() << endl;
                        exit( 1 );
                }

                g_basedn = args["basedn"];
                g_dnsttl = args.mustDo( "dnsttl" );
                typedef boost::function<void(unsigned int, const DNSName &, const string &, const string &, int)> callback_t;
                callback_t callback = callback_simple;
                if( args["layout"] == "tree" )
                {
                        callback=callback_tree;
                }

                if ( args.mustDo( "pdns-info" ) ) {
                        g_pdnsinfo = true;
                        if( args["metadata-dn"].empty() ) {
                                cerr << "You must set --metadata-dn when using --pdns-info" << endl;
                                exit( 1 );
                        }
                        g_metadatadn = args["metadata-dn"];
                }
                else {
                        g_pdnsinfo = false;
                }

                if ( !args["domainid"].empty() )
                        g_domainid = pdns_stou( args["domainid"] );
                else
                        g_domainid = 1;

                if( !args["named-conf"].empty() )
                {
                        BP.setVerbose( args.mustDo( "verbose" ) );
                        BP.parse( args["named-conf"] );
//                        ZP.setDirectory( BP.getDirectory() );
                        const vector<BindDomainInfo> &domains = BP.getDomains();

                        for(const auto& i: domains)
                        {
                                        if(i.type!="master" && i.type!="slave") {
                                                cerr<<" Warning! Skipping '"<<i.type<<"' zone '"<<i.name<<"'"<<endl;
                                                continue;
                                        }
                                try
                                {
                                  if( i.name != g_rootdnsname && i.name != DNSName("localhost") && i.name != DNSName("0.0.127.in-addr.arpa") )
                                        {
                                                cerr << "Parsing file: " << i.filename << ", domain: " << i.name << endl;
                                                g_zonename = i.name;
                                                ZoneParserTNG zpt(i.filename, i.name, BP.getDirectory());
                                                zpt.setMaxGenerateSteps(args.asNum("max-generate-steps"));
                                                DNSResourceRecord rr;
                                                while(zpt.get(rr)) {
                                                        callback(g_domainid, rr.qname, rr.qtype.getName(), encode_non_ascii(rr.content), rr.ttl);
                                                        if( rr.qtype == QType::SOA )
                                                                ++g_domainid;
                                                }
                                        }
                                }
                                catch( PDNSException &ae )
                                {
                                        cerr << "Fatal error: " << ae.reason << endl;
                                        if( !args.mustDo( "resume" ) )
                                        {
                                                return 1;
                                        }
                                }
                        }
                }
                else
                {
                        if( args["zone-file"].empty() || args["zone-name"].empty() )
                        {
                                        cerr << "Error: At least zone-file and zone-name are required" << endl;
                                        return 1;
                        }

                        g_zonename = DNSName(args["zone-name"]);
                        ZoneParserTNG zpt(args["zone-file"], g_zonename);
                        zpt.setMaxGenerateSteps(args.asNum("max-generate-steps"));
                        DNSResourceRecord rr;
                        while(zpt.get(rr)) {
                                callback(g_domainid, rr.qname, rr.qtype.getName(), encode_non_ascii(rr.content), rr.ttl);
                                if ( rr.qtype == QType::SOA )
                                        ++g_domainid;
                        }
                }
        }
        catch( PDNSException &ae )
        {
                cerr << "Fatal error: " << ae.reason << endl;
                return 1;
        }
        catch( std::exception &e )
        {
                cerr << "Died because of STL error: " << e.what() << endl;
                return 1;
        }
        catch( ... )
        {
                cerr << "Died because of unknown exception" << endl;
                return 1;
        }

        return 0;
}
