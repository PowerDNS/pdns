/*
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
*/#include "utility.hh"
#include "ws.hh"
#include "webserver.hh"
#include "logger.hh"
#include "statbag.hh"
#include "misc.hh"
#include "arguments.hh"
#include "dns.hh"

extern StatBag S;

StatWebServer::StatWebServer()
{
  d_start=time(0);
	d_min10=d_min5=d_min1=0;
}

void StatWebServer::go()
{
  S.doRings();
  pthread_create(&d_tid, 0, threadHelper, this);
  pthread_create(&d_tid, 0, statThreadHelper, this);
}



void StatWebServer::statThread()
{
  try {
    for(;;) {
      d_queries.submit(S.read("udp-queries"));
      d_cachehits.submit(S.read("packetcache-hit"));
      d_cachemisses.submit(S.read("packetcache-miss"));
      d_qcachehits.submit(S.read("query-cache-hit"));
      d_qcachemisses.submit(S.read("query-cache-miss"));
      Utility::sleep(1);
    }
  }
  catch(...) {
    L<<Logger::Error<<"Webserver statThread caught an exception, dying"<<endl;
    exit(1);
  }
}

void *StatWebServer::statThreadHelper(void *p)
{
  StatWebServer *sws=static_cast<StatWebServer *>(p);
  sws->statThread();
  return 0; // never reached
}


void *StatWebServer::threadHelper(void *p)
{
  StatWebServer *sws=static_cast<StatWebServer *>(p);
  sws->launch();
  return 0; // never reached
}

void printtable(ostringstream &ret, const string &ringname, const string &title, int limit=10)
{
  int tot=0;
  int entries=0;
  vector<pair <string,int> >ring=S.getRing(ringname);

  for(vector<pair<string,int> >::const_iterator i=ring.begin(); i!=ring.end();++i) {  
    tot+=i->second;
    entries++;
  }


  ret<<"<table border=1><tr><td colspan=3 bgcolor=#0000ff>"
    "<a href=?ring="<<ringname<<"><font color=#ffffff>Top-"<<limit<<" of ";
  ret<<entries<<": "<<title<<"</a></td>"<<endl;

  ret<<"<tr><td colspan=3><table bgcolor=#ff0000 width=100%><tr><td align=left>"
    "<a href=?resetring="<<ringname<<"><font color=#ffffff>Reset</a></td>";
  ret<<"<td align=right>Resize: ";
  
  int sizes[]={10,100,500,1000,10000,500000,0};
  for(int i=0;sizes[i];++i) {
    if(S.getRingSize(ringname)!=sizes[i])
      ret<<"<a href=?resizering="<<ringname<<"&size="<<sizes[i]<<">"<<sizes[i]<<"</a> ";
    else
      ret<<"("<<sizes[i]<<") ";
  }
  ret<<"</td></table>"<<endl;


  int printed=0;
  for(vector<pair<string,int> >::const_iterator i=ring.begin();limit && i!=ring.end();++i,--limit) {
    ret<<"<tr><td>"<<i->first<<"</td><td>"<<i->second<<"</td><td align=right>"<<setprecision(2)<<i->second*100.0/tot<<"%</td>"<<endl;
    printed+=i->second;
  }
  ret<<"<tr><td colspan=3></td></tr>"<<endl;
  if(printed!=tot)
    ret<<"<tr><td><b>Rest:</b></td><td><b>"<<tot-printed<<"</b></td><td align=right><b>"<<setprecision(2)<<(tot-printed)*100.0/tot<<"%</b></td>"<<endl;

  ret<<"<tr><td><b>Total:</b></td><td><b>"<<tot<<"</td><td align=right><b>100%</b></td>";
  ret<<"</table><p>"<<endl;
}

void StatWebServer::printvars(ostringstream &ret)
{
  ret<<"<table border=1><tr><td colspan=3 bgcolor=#0000ff><font color=#ffffff>Variables</td>"<<endl;
  

  vector<string>entries=S.getEntries();
  for(vector<string>::const_iterator i=entries.begin();i!=entries.end();++i) {
    ret<<"<tr><td>"<<*i<<"</td><td>"<<S.read(*i)<<"</td><td>"<<S.getDescrip(*i)<<"</td>"<<endl;
  }
}

void StatWebServer::printargs(ostringstream &ret)
{
  ret<<"<table border=1><tr><td colspan=3 bgcolor=#0000ff><font color=#ffffff>Arguments</td>"<<endl;

  vector<string>entries=arg().list();
  for(vector<string>::const_iterator i=entries.begin();i!=entries.end();++i) {
    ret<<"<tr><td>"<<*i<<"</td><td>"<<arg()[*i]<<"</td><td>"<<arg().getHelp(*i)<<"</td>"<<endl;
  }
}


string StatWebServer::indexfunction(const map<string,string> &varmap, void *ptr, bool *custom)
{

  StatWebServer *sws=static_cast<StatWebServer *>(ptr);
  map<string,string>rvarmap=varmap;
  if(!rvarmap["resetring"].empty()){
    *custom=true;
    S.resetRing(rvarmap["resetring"]);
    return "HTTP/1.1 301 Moved Permanently\nLocation: /\nConnection: close\n\n";
  }
  if(!rvarmap["resizering"].empty()){
    *custom=true;
    S.resizeRing(rvarmap["resizering"], atoi(rvarmap["size"].c_str()));
    return "HTTP/1.1 301 Moved Permanently\nLocation: /\nConnection: close\n\n";
  }

  ostringstream ret;

  ret<<"<html><head><title>PowerDNS Operational Monitor</title></head><body bgcolor=#ffffff>"<<endl;


  if(rvarmap["ring"].empty())
    ret<<"<h2>PDNS "VERSION" Main Page</h2>"<<endl;
  else
    ret<<"<h2>Details page</h2><a href=/>Back to main page</a><p>"<<endl;

  time_t passed=time(0)-s_starttime;

  ret<<"Uptime: ";
  ret<<humanDuration(passed)<<endl;


  ret<<"Queries/second, 1, 5, 10 minute averages:  "<<setprecision(3)<<
    sws->d_queries.get1()<<", "<<
    sws->d_queries.get5()<<", "<<
    sws->d_queries.get10()<<". Max queries/second: "<<sws->d_queries.getMax()<<
    "<br>"<<endl;
  
  if(sws->d_cachemisses.get10()+sws->d_cachehits.get10()>0)
    ret<<"Cache hitrate, 1, 5, 10 minute averages: "<<setprecision(2)<<
      (sws->d_cachehits.get1()*100.0)/((sws->d_cachehits.get1())+(sws->d_cachemisses.get1()))<<"%, "<<
      (sws->d_cachehits.get5()*100.0)/((sws->d_cachehits.get5())+(sws->d_cachemisses.get5()))<<"%, "<<
      (sws->d_cachehits.get10()*100.0)/((sws->d_cachehits.get10())+(sws->d_cachemisses.get10()))<<
      "%<br>"<<endl;

  if(sws->d_qcachemisses.get10()+sws->d_qcachehits.get10()>0)
    ret<<"Backend query cache hitrate, 1, 5, 10 minute averages: "<<setprecision(2)<<
      (sws->d_qcachehits.get1()*100.0)/((sws->d_qcachehits.get1())+(sws->d_qcachemisses.get1()))<<"%, "<<
      (sws->d_qcachehits.get5()*100.0)/((sws->d_qcachehits.get5())+(sws->d_qcachemisses.get5()))<<"%, "<<
      (sws->d_qcachehits.get10()*100.0)/((sws->d_qcachehits.get10())+(sws->d_qcachemisses.get10()))<<
      "%<br>"<<endl;

  ret<<"Backend query load, 1, 5, 10 minute averages: "<<setprecision(3)<<
    sws->d_qcachemisses.get1()<<", "<<
    sws->d_qcachemisses.get5()<<", "<<
    sws->d_qcachemisses.get10()<<". Max queries/second: "<<sws->d_qcachemisses.getMax()<<
    "<br>"<<endl;

  ret<<"Total queries: "<<S.read("udp-queries")<<". Question/answer latency: "<<S.read("latency")/1000.0<<"ms<p>"<<endl;
  if(rvarmap["ring"].empty()) {
    vector<string>entries=S.listRings();
    for(vector<string>::const_iterator i=entries.begin();i!=entries.end();++i)
      printtable(ret,*i,S.getRingTitle(*i));

    sws->printvars(ret);
    if(arg().mustDo("webserver-print-arguments"))
      sws->printargs(ret);
  }
  else
    printtable(ret,rvarmap["ring"],S.getRingTitle(rvarmap["ring"]),100);

  ret<<"</body></html>"<<endl;

  return ret.str();
}

void StatWebServer::launch()
{
  try {
    WebServer ws(arg()["webserver-address"], arg().asNum("webserver-port"),arg()["webserver-password"]);
    ws.setCaller(this);
    ws.registerHandler("",&indexfunction);
    ws.go();
  }
  catch(...) {
    L<<Logger::Error<<"StatWebserver thread caught an exception, dying"<<endl;
    exit(1);
  }
}
