/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002  PowerDNS.COM BV

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
#include "utility.hh"
#include "webserver.hh"
#include "session.hh"
#include "misc.hh"
#include <vector>
#include "logger.hh"
#include <stdio.h>
#include "dns.hh"


map<string,WebServer::HandlerFunction *>WebServer::d_functions;
void *WebServer::d_that;
string WebServer::d_password;

char WebServer::B64Decode1(char cInChar)
{
  // The incoming character will be A-Z, a-z, 0-9, +, /, or =.
  // The idea is to quickly determine which grouping the
  // letter belongs to and return the associated value
  // without having to search the global encoding string
  // (the value we're looking for would be the resulting
  // index into that string).
  //
  // To do that, we'll play some tricks...
  unsigned char iIndex = '\0';
  switch ( cInChar ) {
  case '+':
    iIndex = 62;
    break;

  case '/':
    iIndex = 63;
    break;

  case '=':
    iIndex = 0;
    break;

  default:
    // Must be 'A'-'Z', 'a'-'z', '0'-'9', or an error...
    //
    // Numerically, small letters are "greater" in value than
    // capital letters and numerals (ASCII value), and capital
    // letters are "greater" than numerals (again, ASCII value),
    // so we check for numerals first, then capital letters,
    // and finally small letters.
    iIndex = '9' - cInChar;
    if ( iIndex > 0x3F ) {
      // Not from '0' to '9'...
      iIndex = 'Z' - cInChar;
      if ( iIndex > 0x3F ) {
	// Not from 'A' to 'Z'...
	iIndex = 'z' - cInChar;
	if ( iIndex > 0x3F ) {
	  // Invalid character...cannot
	  // decode!
	  iIndex = 0x80; // set the high bit
	} // if
	else {
	  // From 'a' to 'z'
	  iIndex = (('z' - iIndex) - 'a') + 26;
	} // else
      } // if
      else {
	// From 'A' to 'Z'
	iIndex = ('Z' - iIndex) - 'A';
      } // else
    } // if
    else {
      // Adjust the index...
      iIndex = (('9' - iIndex) - '0') + 52;
    } // else
    break;

  } // switch

  return iIndex;
}

int WebServer::B64Decode(const std::string& strInput, std::string& strOutput)
{
  // Set up a decoding buffer
  long cBuf = 0;
  char* pBuf = (char*)&cBuf;

  // Decoding management...
  short iBitGroup = 0, iInNum = 0;

  // While there are characters to process...
  //
  // We'll decode characters in blocks of 4, as
  // there are 4 groups of 6 bits in 3 bytes. The
  // incoming Base64 character is first decoded, and
  // then it is inserted into the decode buffer
  // (with any relevant shifting, as required).
  // Later, after all 3 bytes have been reconsituted,
  // we assign them to the output string, ultimately
  // to be returned as the original message.
  int iInSize = strInput.size();
  unsigned char cChar = '\0';
  while ( iInNum < iInSize ) {
    // Fill the decode buffer with 4 groups of 6 bits
    cBuf = 0; // clear
    for ( iBitGroup = 0; iBitGroup < 4; ++iBitGroup ) {
      if ( iInNum < iInSize ) {
	// Decode a character
	cChar = B64Decode1(strInput.at(iInNum++));
      } // if
      else {
	// Decode a padded zero
	cChar = '\0';
      } // else

      // Check for valid decode
      if ( cChar > 0x7F )
	return -1;

      // Adjust the bits
      switch ( iBitGroup ) {
      case 0:
	// The first group is copied into
	// the least significant 6 bits of
	// the decode buffer...these 6 bits
	// will eventually shift over to be
	// the most significant bits of the
	// third byte.
	cBuf = cBuf | cChar;
	break;

      default:
	// For groupings 1-3, simply shift
	// the bits in the decode buffer over
	// by 6 and insert the 6 from the
	// current decode character.
	cBuf = (cBuf << 6) | cChar;
	break;

      } // switch
    } // for

    // Interpret the resulting 3 bytes...note there
    // may have been padding, so those padded bytes
    // are actually ignored.
    strOutput += pBuf[2];
    strOutput += pBuf[1];
    strOutput += pBuf[0];
  } // while

  return 1;
}




void WebServer::registerHandler(const string&s, HandlerFunction *ptr)
{
  d_functions[s]=ptr;
}

void WebServer::setCaller(void *that)
{
  d_that=that;
}

void *WebServer::serveConnection(void *p)
{
  Session *client=static_cast<Session *>(p);
  try {
    string line;
    client->getLine(line);
    stripLine(line);
    //    L<<"page: "<<line<<endl;

    vector<string> parts;
    stringtok(parts,line);
    
    string uri;
    if(parts.size()>1)
      uri=parts[1];

    vector<string>variables;

    parts.clear();
    stringtok(parts,uri,"?");

    //    L<<"baseUrl: '"<<parts[0]<<"'"<<endl;
    
    vector<string>urlParts;
    stringtok(urlParts,parts[0],"/");
    string baseUrl;
    if(urlParts.empty())
      baseUrl="";
    else
      baseUrl=urlParts[0];

    //    L<<"baseUrl real: '"<<baseUrl<<"'"<<endl;

    if(parts.size()>1) {
      stringtok(variables,parts[1],"&");
    }

    map<string,string>varmap;

    for(vector<string>::const_iterator i=variables.begin();
	i!=variables.end();++i) {

      parts.clear();
      stringtok(parts,*i,"=");
      if(parts.size()>1)
	varmap[parts[0]]=parts[1];
      else
	varmap[parts[0]]="";

    }

    bool authOK=0;

    // read & ignore other lines
    do {
      client->getLine(line);
      stripLine(line);

      if(!toLower(line).find("authorization: basic ")) {
	string cookie=line.substr(21);
	string plain;

	B64Decode(cookie,plain);
	vector<string>cparts;
	stringtok(cparts,plain,":");

	if(cparts.size()==2 && !strcmp(cparts[1].c_str(),d_password.c_str())) { // this gets rid of terminating zeros
	  authOK=1;
	}
      }
    }while(!line.empty());


    if(!d_password.empty() && !authOK) {
      client->putLine("HTTP/1.1 401 OK\n");
      client->putLine("WWW-Authenticate: Basic realm=\"PowerDNS\"\n");
      
      client->putLine("Connection: close\n");
      client->putLine("Content-type: text/html\n\n");
      client->putLine("Please enter a valid password!\n");
      client->close();
      delete client;
      return 0;
    }

    HandlerFunction *fptr;
    if((fptr=d_functions[baseUrl])) {
      
      bool custom;
      string ret=(*fptr)(varmap, d_that, &custom);

      if(!custom) {
	client->putLine("HTTP/1.1 200 OK\n");
	client->putLine("Connection: close\n");
	client->putLine("Content-type: text/html\n\n");
      }
      client->putLine(ret);
    }
    else {
      client->putLine("HTTP/1.1 404 Not found\n");
      client->putLine("Connection: close\n");
      client->putLine("Content-type: text/html\n\n");
      // FIXME: CSS problem?
      client->putLine("<html><body><h1>Did not find file '"+baseUrl+"'</body></html>\n");
    }
        
    client->close();
    delete client;
    client=0;
    return 0;

  }
  catch(SessionTimeoutException &e) {
    L<<Logger::Error<<"Timeout in webserver"<<endl;
  }
  catch(SessionException &e) {
    L<<Logger::Error<<"Fatal error in webserver: "<<e.reason<<endl;
  }
  catch(Exception &e) {
    L<<Logger::Error<<"Exception in webserver: "<<e.reason<<endl;
  }
  catch(exception &e) {
    L<<Logger::Error<<"STL Exception in webserver: "<<e.what()<<endl;
  }
  catch(...) {
    L<<Logger::Error<<"Unknown exception in webserver"<<endl;
  }
  if(client) {
    client->close();
    delete client;
    client=0;
  }
  return 0;
}

WebServer::WebServer(const string &listenaddress, int port, const string &password)
{
  d_listenaddress=listenaddress;
  d_port=port;
  d_password=password;
}

void WebServer::go()
{
  try {
    Server *s=new Server(d_port, d_listenaddress);
    
    Session *client;
    pthread_t tid;
    
    L<<Logger::Error<<"Launched webserver on "<<d_listenaddress<<":"<<d_port<<endl;

    while((client=s->accept())) {
      pthread_create(&tid, 0 , &serveConnection, (void *)client);
    }
  }
  catch(SessionTimeoutException &e) {
    L<<Logger::Error<<"Timeout in webserver"<<endl;
  }
  catch(SessionException &e) {
    L<<Logger::Error<<"Fatal error in webserver: "<<e.reason<<endl;
  }
  catch(Exception &e) {
    L<<Logger::Error<<"Fatal error in main webserver thread: "<<e.reason<<endl;
  }
  catch(exception &e) {
    L<<Logger::Error<<"STL Exception in main webserver thread: "<<e.what()<<endl;
  }
  catch(...) {
    L<<Logger::Error<<"Unknown exception in main webserver thread"<<endl;
  }
  exit(1);

}
