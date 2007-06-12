/*
 *  PowerDNS BIND Zone to LDAP converter
 *  Copyright (C) 2003  Norbert Sendetzky
 *  Copyright (C) 2007  bert hubert
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  the Free Software Foundation
 *  
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


#include <map>
#include <string>
#include <iostream>
#include <stdio.h>
#include "arguments.hh"
#include "bindparser.hh"
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
string g_basedn;
string g_zonename;
map<string,bool> g_objects;

static void callback_simple( unsigned int domain_id, const string &domain, const string &qtype, const string &content, int ttl, int prio )
{
	string host;
	string::size_type pos;
	vector<string> parts;
	string domain2 = stripDot( domain );


	if( ( pos = domain2.rfind( g_zonename ) ) == string::npos )
	{
		cerr << "Domain " << domain2 << " not part of " << g_zonename << endl;
		return;
	}

	host = stripDot( domain2.substr( 0, pos ) );

	cout << "dn: dc=";
	if( !host.empty() ) { cout << host << ",dc="; }
	cout << g_zonename << "," << g_basedn << endl;

	if( host.empty() ) { host = g_zonename; }

	if( !g_objects[domain2] )
	{
		g_objects[domain2] = true;

		cout << "changetype: add" << endl;
		cout << "objectclass: dnsdomain2" << endl;
		cout << "objectclass: domainrelatedobject" << endl;
		cout << "dc: " << host << endl;
		if( g_dnsttl ) { cout << "dnsttl: " << ttl << endl; }
		cout << "associateddomain: " << domain2 << endl;
	}
	else
	{
		cout << "changetype: modify" << endl;
		cout << "add: " << qtype << "Record" << endl;
	}

	cout << qtype << "Record: ";
	if( prio != 0 ) { cout << prio << " "; }
	cout << stripDot( content ) << endl << endl;
}



static void callback_tree( unsigned int domain_id, const string &domain, const string &qtype, const string &content, int ttl, int prio )
{
	unsigned int i;
	string dn, net;
	vector<string> parts;
	string domain2 = stripDot( domain );

	stringtok( parts, domain2, "." );
	if( parts.empty() ) { return; }

	for( i = parts.size() - 1; i > 0; i-- )
	{
		net = parts[i] + net;
		dn = "dc=" + parts[i] + "," + dn;

		if( !g_objects[net] )
		{
			g_objects[net] = true;

			cout << "dn: " << dn << g_basedn << endl;
			cout << "changetype: add" << endl;
			cout << "objectclass: dnsdomain2" << endl;
			cout << "objectclass: domainrelatedobject" << endl;
			cout << "dc: " << parts[i] << endl;
			cout << "associateddomain: " << net << endl << endl;
		}

		net = "." + net;
	}

	cout << "dn: " << "dc=" << parts[0] << "," << dn << g_basedn << endl;

	if( !g_objects[domain2] )
	{
		g_objects[domain2] = true;

		cout << "changetype: add" << endl;
		cout << "objectclass: dnsdomain2" << endl;
		cout << "objectclass: domainrelatedobject" << endl;
		cout << "dc: " << parts[0] << endl;
		if( g_dnsttl ) { cout << "dnsttl: " << ttl << endl; }
		cout << "associateddomain: " << domain2 << endl;
	}
	else
	{
		cout << "changetype: modify" << endl;
		cout << "add: " << qtype << "Record" << endl;
	}

	cout << qtype << "Record: ";
	if( prio != 0 ) { cout << prio << " "; }
	cout << stripDot( content ) << endl << endl;
}



int main( int argc, char* argv[] )
{
	BindParser BP;
	vector<string> parts;


	try
	{
#if __GNUC__ >= 3
		ios_base::sync_with_stdio( false );
#endif
		reportAllTypes();
		args.setCmd( "help", "Provide a helpful message" );
		args.setSwitch( "verbose", "Verbose comments on operation" ) = "no";
		args.setSwitch( "resume", "Continue after errors" ) = "no";
		args.setSwitch( "dnsttl", "Add dnsttl attribute to every entry" ) = "no";
		args.set( "named-conf", "Bind 8 named.conf to parse" ) = "";
		args.set( "zone-file", "Zone file to parse" ) = "";
		args.set( "zone-name", "Specify a zone name if zone is set" ) = "";
		args.set( "basedn", "Base DN to store objects below" ) = "ou=hosts,o=mycompany,c=de";
		args.set( "layout", "How to arrange entries in the directory (simple or as tree)" ) = "simple";

		args.parse( argc, argv );

		if( argc < 2 || args.mustDo( "help" ) )
		{
			cerr << "Syntax:" << endl << endl;
			cerr << args.helpstring() << endl;
			exit( 1 );
		}

		g_basedn = args["basedn"];
		g_dnsttl = args.mustDo( "dnsttl" );
		typedef boost::function<void(unsigned int, const string &, const string &, const string &, int, int)> callback_t;
		callback_t callback = callback_simple;
		if( args["layout"] == "tree" )
		{
			callback=callback_tree;
		}

		if( !args["named-conf"].empty() )
		{
			BP.setVerbose( args.mustDo( "verbose" ) );
			BP.parse( args["named-conf"] );
//			ZP.setDirectory( BP.getDirectory() );
			const vector<BindDomainInfo> &domains = BP.getDomains();

			for( vector<BindDomainInfo>::const_iterator i = domains.begin(); i != domains.end(); i++ )
			{
				try
				{
					if( i->name != "." && i->name != "localhost" && i->name != "0.0.127.in-addr.arpa" )
					{
						cerr << "Parsing file: " << i->filename << ", domain: " << i->name << endl;
						g_zonename = i->name;
						ZoneParserTNG zpt(i->filename, i->name, BP.getDirectory());
						DNSResourceRecord rr;
						while(zpt.get(rr))
							callback(0, rr.qname, rr.qtype.getName(), rr.content, rr.ttl, rr.priority);
					}
				}
				catch( AhuException &ae )
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

			g_zonename = args["zone-name"];
			ZoneParserTNG zpt(args["zone-file"], args["zone-name"]);
			DNSResourceRecord rr;
			while(zpt.get(rr))
				callback(0, rr.qname, rr.qtype.getName(), rr.content, rr.ttl, rr.priority);
		}
	}
	catch( AhuException &ae )
	{
		cerr << "Fatal error: " << ae.reason << endl;
		return 1;
	}
	catch( exception &e )
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
