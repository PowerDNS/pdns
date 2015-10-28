#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <string>
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

deque<string> segmentDNSName(const string& input )
{
  // cerr<<"segmentDNSName("<<input<<")"<<endl; 
%%{
        machine dnsname;
        write data;
        alphtype unsigned char;
}%%
	(void)dnsname_error;  // silence warnings
	(void)dnsname_en_main;

        deque<string> ret;

        string realinput;
        if(input.empty() || input == ".") return ret;

        if(input[input.size()-1]!='.') realinput=input+".";  // FIXME400 YOLO
        else realinput=input;

        const char *p = realinput.c_str(), *pe = realinput.c_str() + realinput.length();
        const char* eof = pe;
        int cs;
        char val = 0;

        string label;
	label.reserve(10);
        %%{
                action labelEnd { 
                        ret.push_back(label);
                        label.clear();
                }
                action labelBegin { 
                        label.clear();
                }

                action reportEscaped {
                  char c = *fpc;
                  label.append(1, c);
                }
                action reportEscapedNumber {
                  char c = *fpc;
                  val *= 10;
                  val += c-'0';
                  
                }
                action doneEscapedNumber {
                  label.append(1, val);
                  val=0;
                }
                
                action reportPlain {
                  label.append(1, *(fpc));
                }

                escaped = '\\' (([^0-9]@reportEscaped) | ([0-9]{3}$reportEscapedNumber%doneEscapedNumber));
                plain = (extend-'\\'-'.') $ reportPlain;
                labelElement = escaped | plain;            

                main := ((labelElement+ '.') >labelBegin %labelEnd)+;

                # Initialize and execute.
                write init;
                write exec;
        }%%

        if ( cs < dnsname_first_final ) {
                throw runtime_error("Unable to parse DNS name '"+input+"' ('"+realinput+"'): cs="+std::to_string(cs));
        }

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
