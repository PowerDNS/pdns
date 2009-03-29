/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002 - 2009  PowerDNS.COM BV

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
#ifndef WS_HH
#define WS_HH
#include <string>
#include <map>
#include <time.h>
#include <pthread.h>
#include <sstream>
#include <iomanip>

#ifndef WIN32
# include <unistd.h>
#endif // WIN32

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif // HAVE_CONFIG_H

#include "misc.hh"
using namespace std;

class Ewma
{
public:
  Ewma() : d_last(0), d_10(0), d_5(0), d_1(0), d_max(0){dt.set();}
  void submit(int val) 
  {
    int rate=val-d_last;
    double difft=dt.udiff()/1000000.0;
    dt.set();
    
    d_10=((600.0-difft)*d_10+(difft*rate))/600.0;
    d_5=((300.0-difft)*d_5+(difft*rate))/300.0;
    d_1=((60.0-difft)*d_1+(difft*rate))/60.0;
    d_max=max(d_1,d_max);
      
    d_last=val;
  }
  double get10()
  {
    return d_10;
  }
  double get5()
  {
    return d_5;
  }
  double get1()
  {
    return d_1;
  }
  double getMax()
  {
    return d_max;
  }
private:
  DTime dt;
  int d_last;
  double d_10, d_5, d_1, d_max;
};


class StatWebServer
{
public:
  StatWebServer();
  void go();
  static string makePercentage(const double& val);
private:
  static void *threadHelper(void *);
  static void *statThreadHelper(void *p);
  static string indexfunction(const map<string,string> &varmap, void *ptr, bool *custom);

  void printvars(ostringstream &ret);
  void printargs(ostringstream &ret);
  void launch();
  void statThread();
  pthread_t d_tid;

  time_t d_start;
  double d_min10, d_min5, d_min1;
  Ewma d_queries, d_cachehits, d_cachemisses;
  Ewma d_qcachehits, d_qcachemisses;
};

#endif
