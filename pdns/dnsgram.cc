/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * In addition, for the avoidance of any doubt, permission is granted to
 * link this program with OpenSSL and to (re)distribute the binaries
 * produced as the result of such linking.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#define __FAVOR_BSD
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "statbag.hh"
#include "dnspcap.hh"
#include "dnsrecords.hh"
#include "dnsparser.hh"
#include <boost/tuple/tuple.hpp>
#include <boost/tuple/tuple_comparison.hpp>
#include <map>
#include <set>
#include <fstream>
#include <algorithm>
#include "anadns.hh"

#include "namespaces.hh"
#include "namespaces.hh"

StatBag S;

static struct tm* pdns_localtime_r(const uint32_t* then, struct tm* tm)
{
  time_t t = *then;
  
  return localtime_r(&t, tm);
}

int32_t g_clientQuestions, g_clientResponses, g_serverQuestions, g_serverResponses, g_skipped;
struct pdns_timeval g_lastanswerTime, g_lastquestionTime;

static void makeReport(const struct pdns_timeval& tv)
{
  int64_t clientdiff = g_clientQuestions - g_clientResponses;
  int64_t serverdiff = g_serverQuestions - g_serverResponses;

  if(clientdiff > 1 && clientdiff > 0.02*g_clientQuestions) {
    char tmp[80];
    struct tm tm=*pdns_localtime_r(&tv.tv_sec, &tm);
    strftime(tmp, sizeof(tmp) - 1, "%F %H:%M:%S", &tm);

    cout << tmp << ": Resolver dropped too many questions (" 
         << g_clientQuestions <<" vs " << g_clientResponses << "), diff: " <<clientdiff<<endl;

    tm=*pdns_localtime_r(&g_lastanswerTime.tv_sec, &tm);
    strftime(tmp, sizeof(tmp) - 1, "%F %H:%M:%S", &tm);
    
    cout<<"Last answer: "<<tmp<<"."<<g_lastanswerTime.tv_usec/1000000.0<<endl;

    tm=*pdns_localtime_r(&g_lastquestionTime.tv_sec, &tm);
    strftime(tmp, sizeof(tmp) - 1, "%F %H:%M:%S", &tm);
    
    cout<<"Last question: "<<tmp<<"."<<g_lastquestionTime.tv_usec/1000000.0<<endl;
  }

  if(serverdiff > 1 && serverdiff > 0.02*g_serverQuestions) {
    char tmp[80];
    struct tm tm=*pdns_localtime_r(&tv.tv_sec, &tm);
    strftime(tmp, sizeof(tmp) - 1, "%F %H:%M:%S", &tm);

    cout << tmp << ": Auth server dropped too many questions (" 
         << g_serverQuestions <<" vs " << g_serverResponses << "), diff: " <<serverdiff<<endl;

    tm=*pdns_localtime_r(&g_lastanswerTime.tv_sec, &tm);
    strftime(tmp, sizeof(tmp) - 1, "%F %H:%M:%S", &tm);
    
    cout<<"Last answer: "<<tmp<<"."<<g_lastanswerTime.tv_usec/1000000.0<<endl;

    tm=*pdns_localtime_r(&g_lastquestionTime.tv_sec, &tm);
    strftime(tmp, sizeof(tmp) - 1, "%F %H:%M:%S", &tm);
    
    cout<<"Last question: "<<tmp<<"."<<g_lastquestionTime.tv_usec/1000000.0<<endl;
  }
//  cout <<"Recursive questions: "<<g_clientQuestions<<", recursive responses: " << g_clientResponses<< 
//    ", server questions: "<<g_serverQuestions<<", server responses: "<<g_serverResponses<<endl;


//  cerr << tv.tv_sec << " " <<g_clientQuestions<<" " << g_clientResponses<< " "<<g_serverQuestions<<" "<<g_serverResponses<<" "<<g_skipped<<endl;
  g_clientQuestions=g_clientResponses=g_serverQuestions=g_serverResponses=0;
  g_skipped=0;
}

static void usage() {
  cerr<<"syntax: dnsgram INFILE..."<<endl;
}

int main(int argc, char** argv)
try
{
  // Parse possible options
  if (argc == 1) {
    usage();
    return EXIT_SUCCESS;
  }

  for(int n=1 ; n < argc; ++n) {
    if ((string) argv[n] == "--help") {
      usage();
      return EXIT_SUCCESS;
    }

    if ((string) argv[n] == "--version") {
      cerr<<"dnsgram "<<VERSION<<endl;
      return EXIT_SUCCESS;
    }
  }

  reportAllTypes();
  for(int n=1 ; n < argc; ++n) {
    cout<<argv[n]<<endl;
    unsigned int parseErrors=0, totalQueries=0, skipped=0;
    PcapPacketReader pr(argv[n]);
    //    PcapPacketWriter pw(argv[n]+string(".out"), pr);
    /* four sorts of packets: 
       "rd": question from a client pc
       "rd qr": answer to a client pc
       "": question from the resolver
       "qr": answer to the resolver */
    
    /* what are interesting events to note? */
    /* we measure every 60 seconds, each interval with 10% less answers than questions is interesting */
    /* report chunked */
    
    struct pdns_timeval lastreport;
    
    typedef set<pair<DNSName, uint16_t> > queries_t;
    queries_t questions, answers;

    //    unsigned int count = 50000;
    
    map<pair<DNSName, uint16_t>, int> counts;

    map<double, int> rdqcounts, rdacounts;

    while(pr.getUDPPacket()) {
      if((ntohs(pr.d_udp->uh_dport)==5300 || ntohs(pr.d_udp->uh_sport)==5300 ||
          ntohs(pr.d_udp->uh_dport)==53   || ntohs(pr.d_udp->uh_sport)==53) &&
         pr.d_len > 12) {
        try {
          MOADNSParser mdp(false, (const char*)pr.d_payload, pr.d_len);

          if(lastreport.tv_sec == 0) {
            lastreport = pr.d_pheader.ts;
          }

          if(mdp.d_header.rd && !mdp.d_header.qr) {
	    rdqcounts[pr.d_pheader.ts.tv_sec + 0.01*(pr.d_pheader.ts.tv_usec/10000)]++;
            g_lastquestionTime=pr.d_pheader.ts;
            g_clientQuestions++;
            totalQueries++;
            counts[make_pair(mdp.d_qname, mdp.d_qtype)]++;
            questions.insert(make_pair(mdp.d_qname, mdp.d_qtype));
          }
          else if(mdp.d_header.rd && mdp.d_header.qr) {
	    rdacounts[pr.d_pheader.ts.tv_sec + 0.01*(pr.d_pheader.ts.tv_usec/10000)]++;
            g_lastanswerTime=pr.d_pheader.ts;
            g_clientResponses++;
            answers.insert(make_pair(mdp.d_qname, mdp.d_qtype));
          }
          else if(!mdp.d_header.rd && !mdp.d_header.qr) {
            g_lastquestionTime=pr.d_pheader.ts;
            g_serverQuestions++;
            counts[make_pair(mdp.d_qname, mdp.d_qtype)]++;
            questions.insert(make_pair(mdp.d_qname, mdp.d_qtype));
            totalQueries++;
          }
          else if(!mdp.d_header.rd && mdp.d_header.qr) {
            answers.insert(make_pair(mdp.d_qname, mdp.d_qtype));
            g_serverResponses++;
          }
          
          if(pr.d_pheader.ts.tv_sec - lastreport.tv_sec >= 1) {
            makeReport(pr.d_pheader.ts);
            lastreport = pr.d_pheader.ts;
          }          
        }
        catch(const MOADNSException &mde) {
          //        cerr<<"error parsing packet: "<<mde.what()<<endl;
          parseErrors++;
          continue;
        }
        catch(std::exception& e) {
          cerr << e.what() << endl;
          continue;
        }
      }
    }

    map<double, pair<int, int>> splot;

    for(auto& a : rdqcounts) {
      splot[a.first].first = a.second;
    }
    for(auto& a : rdacounts) {
      splot[a.first].second = a.second;
    }

    cerr<<"Writing out sub-second rd query/response stats to ./rdqaplot"<<endl;
    ofstream plot("rdqaplot");
    plot<<std::fixed;
    for(auto& a : splot) {
      plot << a.first<<"\t"<<a.second.first<<"\t"<<a.second.second<<endl;
    }
    cerr<<"Parse errors: "<<parseErrors<<", total queries: "<<totalQueries<<endl;
    typedef vector<queries_t::value_type> diff_t;
    diff_t diff;
    set_difference(questions.begin(), questions.end(), answers.begin(), answers.end(), back_inserter(diff));
    cerr<<questions.size()<<" different rd questions, "<< answers.size()<<" different rd answers, diff: "<<diff.size()<<endl;
    cerr<<skipped<<" skipped\n";

    cerr<<"Generating 'failed' file with failed queries and counts\n";
    ofstream failed("failed");
    failed<<"name\ttype\tnumber\n";
    for(diff_t::const_iterator i = diff.begin(); i != diff.end() ; ++i) {
      failed << i->first << "\t" << DNSRecordContent::NumberToType(i->second) << "\t"<< counts[make_pair(i->first, i->second)]<<"\n";
    }

    diff.clear();
    
    set_difference(answers.begin(), answers.end(), questions.begin(), questions.end(), back_inserter(diff));
    cerr<<diff.size()<<" answers w/o questions\n";

    cerr<<"Generating 'succeeded' file with all unique answers and counts\n";
    ofstream succeeded("succeeded");
    succeeded<<"name\ttype\tnumber\n";
    for(queries_t::const_iterator i = answers.begin(); i != answers.end() ; ++i) {
      succeeded << i->first << "\t" <<DNSRecordContent::NumberToType(i->second) << "\t" << counts[make_pair(i->first, i->second)]<<"\n";
    }
  }
}
catch(std::exception& e)
{
  cerr<<"Fatal: "<<e.what()<<endl;
}
