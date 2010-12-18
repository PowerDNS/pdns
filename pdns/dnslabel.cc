/*
    PowerDNS Versatile Database Driven Nameserver
		Copyright (C) 2010 Netherlabs Computer Consulting BV
		
    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2
    as published by the Free Software Foundation    

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

#include "dnslabel.hh"

void DNSLabel::init(unsigned int len)
{
	d_capacity = len;
	d_storage = new char[d_capacity]; 
	
	d_fulllen = 0;
	d_offset = 0;
}

DNSLabel::DNSLabel(const DNSLabel& rhs)
{
	init();
	*this=rhs;
}

DNSLabel::DNSLabel() 
{
	init(); 
	appendChar(0); // "root"
}

// FIXME: this should validate if 'raw' is a valid dns label!
DNSLabel::DNSLabel(const char*raw, unsigned int len)
{
	if(!validateStrict(raw, len)) 
		throw std::range_error("invalid raw label passed to DNSLabel");
	init(len);
	memcpy(d_storage, raw, len);
	d_fulllen = len;
}

DNSLabel& DNSLabel::operator=(const DNSLabel& rhs)
{
	unsigned int newlen = rhs.getLength();
	if(newlen > d_capacity) {
		delete[] d_storage;
		d_storage = new char[newlen];
	}
	d_fulllen = newlen;
	d_offset=0;
	memcpy(d_storage, rhs.d_storage, d_fulllen);
	
	return *this;
}

DNSLabel::~DNSLabel()
{
	delete[] d_storage;
}

DNSLabel::DNSLabel(const char* human)
{
	// FIXME: do the escaping thing
	init();
	const char* labelStart=human;
	const char* p;
	for(p=human; *p; ++p) {
		if(*p=='.') {
			char labelLen = p - labelStart;
			// cerr<<"input, labelLen: "<<(int)labelLen<<endl;
			appendChar(labelLen);
			
			memcpy(d_storage+d_fulllen, labelStart, labelLen);
			d_fulllen += labelLen;
			labelStart=p+1;
		}
	}
	if(labelStart != p) { // human input did not end on a trailing dot
		char labelLen = p - labelStart;
		// cerr<<"trailing input, labelLen: "<<(int)labelLen<<endl;
		d_storage[d_fulllen++]= labelLen;
		memcpy(d_storage + d_fulllen, labelStart, labelLen);
		d_fulllen += labelLen;	
	}
	d_storage[d_fulllen++]=0;
}

bool DNSLabel::validateStrict(const char* raw, unsigned int len)
{
	int result = validateConsume(raw, len);
	if(result < 0 || (unsigned int)result != len)
		return false;
	return true;	
}

int DNSLabel::validateConsume(const char* raw, unsigned int maxLen)
{
	if(!maxLen)
		return -1; // shortest ok label is: '\x00'

	const unsigned char* p = (const unsigned char*) raw;

	for(;;) {
		if(p > (const unsigned char*)raw + maxLen) // beyond the end
			return -1;
			
		if(*p > 64) // label length too long, or a compression pointer
			return -1;
		
		if(!*p) { // final label, return bytes consumed
			return 1 + (p - (const unsigned char*)raw);
		}
		
		p += *p + 1;
	}
	return -1; // we should not get here, but if we do, it's bad
}


string DNSLabel::human() const
{
	// FIXME: do the escaping thing
	const char* p = getStart();
	char labelLen;
	
	if(!*p)
		return ".";
		
	string ret;
	for(;;) {	
		labelLen = *p;
		// cerr<<"human, labelLen: "<<(int) labelLen<<endl;
		++p;
		ret.append(p, (int)labelLen);
		
		
		if(!labelLen)
			break;
		ret.append(1, '.');
		p+=labelLen;
	}
	
	return ret;
}

bool DNSLabel::chopOff()
{
	char labelLen = *getStart();
	d_offset += labelLen+1;
	return labelLen;
}

bool DNSLabel::endsOn(const DNSLabel &rhs) const
{
	int longer = getLength() - rhs.getLength();
	if(longer < 0) 
		return false;
	return !memcmp(getStart()+longer, rhs.getStart(), 
		rhs.getLength());
}

string DNSLabel::binary() const
{
	return std::string(getStart(), getLength());
}

void DNSLabel::expandCapacity()
{
	d_capacity *= 2;
	char *newStorage = new char[d_capacity];
	memcpy(newStorage, d_storage, d_fulllen);
	delete[] d_storage;
	d_storage=newStorage;
}

DNSLabel DNSLabel::createFromBuffer(const char* raw, unsigned int* len)
{
	int result = DNSLabel::validateConsume(raw, *len);
	if(result < 0)
		throw std::runtime_error("raw input to DNSLabel factory was invalid");
	*len = (unsigned int) result;
	return DNSLabel(raw, result);
}

#if 0
void endsOn(const DNSLabel& first, const DNSLabel& second)
{
	cerr<<"Does '"<<first.human()<<"' end on '"<<second.human()<<"': ";
	cerr<<first.endsOn(second)<<endl;
}

string makeHexDump(const string& str)
{
  char tmp[5];
  string ret;
  ret.reserve((int)(str.size()*2.2));

  for(string::size_type n=0;n<str.size();++n) {
    snprintf(tmp,sizeof(tmp), "%02x ", (unsigned char)str[n]);
    ret+=tmp;  
  }
  return ret;
}

int main()
{	
	DNSLabel label("www.powerdns.com"), suffix("powerdns.com"), root;
	endsOn(label, suffix);
	
	suffix=root;
	endsOn(label, suffix);
	
	suffix=DNSLabel("net");
	endsOn(label, suffix);
	
	while(label.chopOff()) {
		cerr<<label.human()<<endl;
		cerr<<endl;
	}
	
	DNSLabel label2("blah");
	label = label2;
	
	
	char rawLabel[]= "\003www\004ds9a\002nl";
	DNSLabel raw(rawLabel, sizeof(rawLabel));
	cerr<<"raw human: "<<raw.human()<<endl;
	
	char rawLabel2[]= "\003www\004ds9a\003nl";
	DNSLabel raw2(rawLabel2, sizeof(rawLabel2));
}
#endif
