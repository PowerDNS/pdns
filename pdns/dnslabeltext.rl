#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <string>
#include "dnsname.hh"
#include "namespaces.hh"
#include "dnswriter.hh"
#include "misc.hh"

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
        unsigned char labellen=0;
        unsigned int lenpos=0;
        %%{
                action labelEnd { 
                        if (labellen > 63) {
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

// Reads an RFC 1035 character string from 'in', puts the resulting bytes in 'out'.
// Returns the amount of bytes read from 'in'
size_t parseRFC1035CharString(const std::string &in, std::string &val) {

  val.clear();
  val.reserve(in.size());
  const char *p = in.c_str();
  const char *pe = p + in.size();
  int cs = 0;
  uint8_t escaped_octet = 0;
  // Keeps track of how many chars we read from the source string
  size_t counter=0;

/* This parses an RFC 1035 char-string.
 * It was created from the ABNF in draft-ietf-dnsop-svcb-https-02 with
 * https://github.com/zinid/abnfc and modified to put all the characters in the
 * right place.
 */
%%{
  machine dns_text_to_string;

  action doEscapedNumber {
    escaped_octet *= 10;
    escaped_octet += fc-'0';
    counter++;
  }

  action doneEscapedNumber {
    val += escaped_octet;
    escaped_octet = 0;
  }

  action addToVal {
    val += fc;
    counter++;
  }

  action incrementCounter {
    counter++;
  }

  # generated rules, define required actions
  DIGIT = 0x30..0x39;
  DQUOTE = "\"";
  HTAB = "\t";
  SP = " ";
  WSP = (SP | HTAB)@addToVal;
  non_special = "!" | 0x23..0x27 | 0x2a..0x3a | 0x3c..0x5b | 0x5d..0x7e;
  non_digit = 0x21..0x2f | 0x3a..0x7e;
  dec_octet = ( ( "0" | "1" ) DIGIT{2} ) | ( "2" ( ( 0x30..0x34 DIGIT ) | ( "5" 0x30..0x35 ) ) );
  escaped = '\\'@incrementCounter ( non_digit$addToVal | dec_octet$doEscapedNumber@doneEscapedNumber );
  contiguous = ( non_special$addToVal | escaped )+;
  quoted = DQUOTE@incrementCounter ( contiguous | ( '\\'? WSP ) )* DQUOTE@incrementCounter;
  char_string = (contiguous | quoted);

  # instantiate machine rules
  main := char_string;
  write data;
  write init;
}%%

  // silence warnings
  (void) dns_text_to_string_first_final;
  (void) dns_text_to_string_error;
  (void) dns_text_to_string_en_main;
  %% write exec;

  return counter;
}

size_t parseSVCBValueListFromParsedRFC1035CharString(const std::string &in, std::vector<std::string> &val) {
  val.clear();
  const char *p = in.c_str();
  const char *pe = p + in.size();
  int cs = 0;
  const char* eof = pe;
  // Keeps track of how many chars we read from the source string
  size_t counter=0;

  // Here we store the parsed value until we hit a comma or are done
  std::string tmp;

%%{
  machine dns_text_to_value_list;
  alphtype unsigned char;

  action addToVal {
    tmp += fc;
    counter++;
  }

  action addToValNoIncrement {
    tmp += fc;
  }

  action addToVector {
    val.push_back(tmp);
    tmp.clear();
    counter++;
  }

  action incrementCounter {
    counter++;
  }

  # generated rules, define required actions
  OCTET = 0x00..0xff;
  item_allowed = 0x00..0x2b | 0x2d..0x5b | 0x5d..0xff;
  escaped_item = ( item_allowed$addToVal | '\\,'$incrementCounter@addToValNoIncrement | '\\\\'$incrementCounter@addToValNoIncrement )+;
  comma_separated = ( escaped_item%addToVector ( ","@incrementCounter escaped_item%addToVector )* )?;

  # instantiate machine rules
  main := comma_separated;
  write data;
  write init;
}%%

  // silence warnings
  (void) dns_text_to_value_list_first_final;
  (void) dns_text_to_value_list_error;
  (void) dns_text_to_value_list_en_main;
  %% write exec;

  if ( cs < dns_text_to_value_list_first_final ) {
          throw runtime_error("Unable to parse DNS SVCB value list '"+in+"'");
  }

  return counter;
}


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
