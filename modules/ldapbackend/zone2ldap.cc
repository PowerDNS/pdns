/*
    PowerDNS BIND Zone to LDAP converter
    Copyright (C) 2003  Norbert Sendetzky

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/


#include <string>
#include <map>
#include <iostream>
#include <stdio.h>

using namespace std;

#include "dns.hh"
#include "arguments.hh"
#include "zoneparser.hh"
#include "bindparser.hh"
#include "statbag.hh"
#include "misc.hh"



StatBag S;
ArgvMap args;
string g_basedn;
string g_zonename;
map<string,bool> g_objects;


static void callback( unsigned int domain_id, const string &domain, const string &qtype, const string &content, int ttl, int prio )
{
	vector<string> parts;
	string domain2 = ZoneParser::canonic( domain );
	string content2 = ZoneParser::canonic( content );


	stringtok( parts, domain2, "." );

	if( parts[0] == g_zonename ) {
		cout << "dn: dc=" << g_zonename << "," << g_basedn << endl;
	}else {
		cout << "dn: dc=" << parts[0] << ",dc=" << g_zonename << "," << g_basedn << endl;
	}

	if( g_objects[domain2] != true )
	{
		g_objects[domain2] = true;
		cout << "changetype: add" << endl;
		cout << "objectclass: top" << endl;
		if( parts[0] == g_zonename ) cout << "objectclass: dcobject" << endl;   // only necessary for phpgeneral, my web based admin interface
		cout << "objectclass: dnsdomain" << endl;
		cout << "objectclass: domainrelatedobject" << endl;
		cout << "dc: " << parts[0] << endl;
		cout << "associateddomain: " << domain2 << endl;
	}
	else
	{
		cout << "changetype: modify" << endl;
	}

	if( prio != 0 ) {
		cout << qtype << "Record: " << prio << " " << content2 << endl << endl;
	} else {
		cout << qtype << "Record: " << content2 << endl << endl;
	}
}


int main( int argc, char* argv[] )
{
	string namedfile = "";
	string zonefile = "";
	vector<string> parts;
	BindParser BP;
	ZoneParser ZP;


	g_basedn = "";
	g_zonename = "";

	try
	{
#if __GNUC__ >= 3
		ios_base::sync_with_stdio( false );
#endif

		args.setCmd( "help", "Provide a helpful message" );
		args.setSwitch( "verbose", "Verbose comments on operation" ) = "no";
		args.setSwitch( "resume", "Continue after errors" ) = "no";
		args.set( "zone", "Zonefile with $ORIGIN to parse" ) = "";
		args.set( "zone-name", "Specify an $ORIGIN in case it is not present" ) = "";
		args.set( "named-conf", "Bind 8 named.conf to parse" ) = "";
		args.set( "basedn", "Base DN to store objects below" ) = "dc=example,dc=org";

		args.parse( argc, argv );

		if( argc < 2 || args.mustDo( "help" ) )
		{
			cerr << "Syntax:" << endl << endl;
			cerr << args.helpstring() << endl;
			exit( 1 );
		}

		g_basedn = args["basedn"];
		namedfile = args["named-conf"];
		zonefile = args["zone"];

		ZP.setCallback( &callback );
		BP.setVerbose( args.mustDo( "verbose" ) );
		BP.parse( namedfile.empty() ? "./named.conf" : namedfile );

		if( zonefile.empty() )
		{
			ZP.setDirectory( BP.getDirectory() );
			const vector<BindDomainInfo> &domains = BP.getDomains();

			for( vector<BindDomainInfo>::const_iterator i = domains.begin(); i != domains.end(); ++i )
			{
				try
				{
					g_objects.clear();
					if( i->name != "." && i->name != "localhost" && i->name.substr( i->name.length() - 5, 5 ) != ".arpa" && i->name.substr( i->name.length() - 8, 8 ) != ".ip6.int" )
					{
						cerr << "Parsing file: " << i->filename << ", domain: " << i->name << endl;
						stringtok( parts, i->name, "." );
						g_zonename = parts[0];
						ZP.parse( i->filename, i->name, 0 );
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
			stringtok( parts, args["zone-name"], "." );
			g_zonename = parts[0];
			g_objects.clear();
			ZP.setDirectory( "." );
			ZP.parse( zonefile, args["zone-name"], 0 );
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
