#include "pdns/utility.hh"
#include "xgdbm.hh"
#include "xtdb.hh"
#include "pdns/ahuexception.hh"
#include "pdns/logger.hh"
#include <stdio.h>
#include <sstream>
#include <iostream>

string stringerror()
{
  return strerror(errno);
}


string escape(const string &name) 
{
  string a;

  for(string::const_iterator i=name.begin();i!=name.end();++i)
    if(*i=='|' || *i=='\\'){
      a+='\\';
      a+=*i;
    }
    else
      a+=*i;
  return a;
}

XDBWrapper *db;

map<string,string>arecords;

void doAList(int domain_id, const string &qname, const string &qtype, const string &content, int ttl)
{
  if(qtype!="A")
    return;
  else arecords[qname]=content;
  
}

void doInsert(int domain_id, const string &qname, const string &qtype, const string &content, int ttl)
{
  static string lastname;
  static string writestr;


  if(!lastname.empty() && lastname!=qname) {
    db->append(lastname,writestr);
    writestr="";
  }
  string rcontent(content);
  if(qtype=="NS") {
    rcontent+="@";
    map<string,string>::const_iterator i=arecords.find(content);
    if(i!=arecords.end())
      rcontent+=i->second;
  }

  ostringstream ostr;
  ostr<<escape(qname)<<"|"<<qtype<<"|"<<escape(rcontent)<<"|"<<3600<<"|"<<0<<"|"<<domain_id<<"|"<<0<<"|";
  writestr+=ostr.str();
    
  lastname=qname;
}

typedef void insertFunc(int domain_id, const string &qname, const string &qtype, const string &content, int ttl);

void walk(FILE *fp, insertFunc *ifp)
{
  char line[1024];
  // 0        'ORG'	'SOA'	'A.GTLD-SERVERS.NET. NSTLD.VERISIGN-GRS.COM. 2002100700 1800 900 604800 86400'	0	3600
  int count=0;
  while(fgets(line,1023,fp)) {
    if(!((count++)%10000))
      cout<<count<<endl;

    int domain_id=atoi(line);
    //      cout<<"id="<<domain_id<<endl;
    char *p=line;
    while(*p++!='\'');
    
    char *q=p;
    while(*++p!='\'');
    
    *p=0;
    //      cout<<"qdomain='"<<q<<"'"<<endl;
    string qname=q;
    p=q;
    
    while(*p++!='\'');
    q=p;
    while(*++p!='\'');
    *p=0;
    //      cout<<"type='"<<q<<"'"<<endl;
    string qtype=q;
    p=q;
    
    while(*p++!='\'');
    q=p;
    while(*++p!='\'');
    *p=0;
    //      cout<<"content='"<<q<<"'"<<endl;
    string content=q;
    p=q;
  
    (*ifp)(domain_id,qname,qtype,content,3600);
  
  }
  (*ifp)(0,"","","",0);
}

int main(int argc, char **argv)
{
  if(argc!=2) {
    cerr<<"syntax: xdb-fill filename"<<endl;
    exit(1);
  }
  FILE *fp=fopen(argv[1],"r");

  try {
    db=new XTDBWrapper("./powerdns.xdb"); //, XDBWrapper::ReadWrite);
    
    walk(fp,&doAList);
    cerr<<"Number of glue records: "<<arecords.size()<<endl;
    fseek(fp,0,SEEK_SET);
    walk(fp,&doInsert);
    delete db;
  }
  catch(XDBException &e) {
    cerr<<"DB Error: "<<e.what<<endl;
  }
  
  
}
