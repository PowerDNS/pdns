#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <string>
#include "dnsname.hh"
#include "namespaces.hh"

namespace {
void appendSplit(vector<string>& ret, string& segment, char c)
{
  if(segment.size()>254) {
    ret.push_back(segment);
    segment.clear();
  }
  segment.append(1, c);
}

}

vector<string> segmentDNSText(const string& input )
{
  // cerr<<"segmentDNSText("<<input<<")"<<endl; 
%%{
        machine dnstext;
        write data;
        alphtype unsigned char;
}%%
	(void)dnstext_error;  // silence warnings
	(void)dnstext_en_main;
        const char *p = input.c_str(), *pe = input.c_str() + input.length();
        const char* eof = pe;
        int cs;
        char val = 0;

        string segment;
        vector<string> ret;

        %%{
                action segmentEnd { 
                        ret.push_back(segment);
                        segment.clear();
                }
                action segmentBegin { 
                        segment.clear();
                }

                action reportEscaped {
                  char c = *fpc;
                  appendSplit(ret, segment, c);
                }
                action reportEscapedNumber {
                  char c = *fpc;
                  val *= 10;
                  val += c-'0';
                  
                }
                action doneEscapedNumber {
                  appendSplit(ret, segment, val);
                  val=0;
                }
                
                action reportPlain {
                  appendSplit(ret, segment, *(fpc));
                }

                escaped = '\\' (([^0-9]@reportEscaped) | ([0-9]{3}$reportEscapedNumber%doneEscapedNumber));
                plain = ((extend-'\\'-'"')|'\n'|'\t') $ reportPlain;
                txtElement = escaped | plain;
            
                main := (('"' txtElement* '"' space?) >segmentBegin %segmentEnd)+;

                # Initialize and execute.
                write init;
                write exec;
        }%%

        if ( cs < dnstext_first_final ) {
                throw runtime_error("Unable to parse DNS TXT '"+input+"'");
        }

        return ret;
};


DNSName::string_t segmentDNSNameRaw(const char* realinput, size_t inputlen)
{
%%{
        machine dnsnameraw;
        write data;
        alphtype unsigned char;
}%%
	(void)dnsnameraw_error;  // silence warnings
	(void)dnsnameraw_en_main;

        DNSName::string_t ret;

        if(!*realinput || *realinput == '.') {
          ret.append(1, (char)0);
          return ret;
        }

        ret.reserve(inputlen+1);

        const char *p = realinput, *pe = realinput + inputlen;
        const char* eof = pe;
        int cs;
        char val = 0;
        char labellen=0;
        unsigned int lenpos=0;
        %%{
                action labelEnd { 
                        if (labellen < 0 || labellen > 63) {
                          throw runtime_error("Unable to parse DNS name '"+string(realinput)+"': invalid label length "+std::to_string(labellen));
                        }
                        ret[lenpos]=labellen;
                        labellen=0;
                }
                action labelBegin { 
                        lenpos=ret.size();
                        ret.append(1, (char)0);
                        labellen=0;
                }

                action reportEscaped {
                  char c = *fpc;
                  ret.append(1, c);
                  labellen++;
                }
                action reportEscapedNumber {
                  char c = *fpc;
                  val *= 10;
                  val += c-'0';
                }
                action doneEscapedNumber {
                  ret.append(1, val);
                  labellen++;
                  val=0;
                }
                
                action reportPlain {
                  ret.append(1, *(fpc));
                  labellen++;
                }

                escaped = '\\' (([^0-9]@reportEscaped) | ([0-9]{3}$reportEscapedNumber%doneEscapedNumber));
                plain = (extend-'\\'-'.') $ reportPlain;
                labelElement = escaped | plain;            

                label = labelElement+ >labelBegin %labelEnd;

                main:=  label ('.' label )* '.'?;

                #main := labelElement((labelElement+ '.') >labelBegin %labelEnd)+;

                #  label = (plain | escaped | escdecb)+ >label_init %label_fin;
                #  dnsname := '.'? label ('.' label >label_sep)* '.'?;

                # Initialize and execute.
                write init;
                write exec;
        }%%

        if ( cs < dnsnameraw_first_final ) {
                throw runtime_error("Unable to parse DNS name '"+string(realinput)+"': cs="+std::to_string(cs));
        }
        ret.append(1, (char)0);
        return ret;
};



#if 0
int main()
{
	//char blah[]="\"blah\" \"bleh\" \"bloeh\\\"bleh\" \"\\97enzo\"";
  char blah[]="\"v=spf1 ip4:67.106.74.128/25 ip4:63.138.42.224/28 ip4:65.204.46.224/27 \\013\\010ip4:66.104.217.176/28 \\013\\010ip4:209.48.147.0/27 ~all\"";
  //char blah[]="\"abc \\097\\098 def\"";
  printf("Input: '%s'\n", blah);
	vector<string> res=dnstext(blah);
  cerr<<res.size()<<" segments"<<endl;
  cerr<<res[0]<<endl;
}
#endif
