#include <string>
#include <vector>
#include <pdns/misc.hh>


#ifndef LDAPBACKEND_UTILS_HH
#define LDAPBACKEND_UTILS_HH

using std::string;
using std::vector;


inline string ptr2ip4( vector<string>& parts )
{
	string ip;
	parts.pop_back();
	parts.pop_back();


	ip = parts.back();
	parts.pop_back();

	while( !parts.empty() )
	{
		ip += "." + parts.back();
		parts.pop_back();
	}

	return ip;
}


inline string ptr2ip6( vector<string>& parts )
{
	int i = 0;
	string ip;


	parts.pop_back();
	parts.pop_back();

	while( i < 3 && parts.size() > 1 )
	{
		if( parts.back() != "0" ) { ip += parts.back(); }
		parts.pop_back();
		i++;
	}
	ip += parts.back();
	parts.pop_back();

	while( !parts.empty() )
	{
		i = 0;
		ip += ":";

		while( i < 3 && parts.size() > 1 )
		{
			if( parts.back() != "0" ) { ip += parts.back(); }
			parts.pop_back();
			i++;
		}
		ip += parts.back();
		parts.pop_back();
	}

	return ip;
}


inline string ip2ptr4( string ip )
{
	string ptr;
	vector<string> parts;

	stringtok( parts, ip, "." );
	while( !parts.empty() )
	{
		ptr += parts.back() +  ".";
		parts.pop_back();
	}

	return ptr + "in-addr.arpa";
}


inline string ip2ptr6( string ip )
{
	string ptr, part, defstr;
	vector<string> parts;

	stringtok( parts, ip, ":" );
	while( !parts.empty() )
	{
		defstr = "0.0.0.0.";
		part = parts.back();

		while( part.length() < 4 )
		{
			part = "0" + part;
		}

		defstr[0] = part[3];
		defstr[2] = part[2];
		defstr[4] = part[1];
		defstr[6] = part[0];
		ptr += defstr;
		parts.pop_back();
	}

	return ptr + "ip6.arpa";
}

#endif
