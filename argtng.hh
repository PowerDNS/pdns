#include <iostream>
#include <stdlib.h>
#include <vector>
#include <map>
#include <string>
#include <cctype>
#include <boost/shared_ptr.hpp>
#include <boost/regex.hpp>
using namespace std;
using namespace boost;

#define decl(x,y) typeof((y)) (x) = (y)

struct cond
{
  virtual bool operator()(const string& s) const=0;
  virtual shared_ptr<cond> copy() const=0;
  virtual ~cond()
  {
  }
};

struct Ok : public cond
{
  bool operator()(const string& s) const
  {
    return true;
  }
  shared_ptr<cond> copy() const
  {
    return shared_ptr<cond>(new Ok);
  }
};

struct Empty : public cond
{
  bool operator()(const string& s) const
  {
    return s.empty();
  }
  shared_ptr<cond> copy() const
  {
    return shared_ptr<cond>(new Empty);
  }
};

struct IpAddress : public cond
{
  bool operator()(const string& s) const
  {
    static const regex r("^((25[0-5]|2[0-4]\\d|[01]\\d\\d|\\d?\\d)\\.){3}(25[0-5]|2[0-4]\\d|[01]\\d\\d|\\d?\\d)$");
    return regex_match(s,r);
  }
  shared_ptr<cond> copy() const
  {
    return shared_ptr<cond>(new IpAddress);
  }
};

struct HostName : public cond
{
  bool operator()(const string& s) const
  {
    static const regex r("^([a-zA-Z0-9_-]\\.)?([a-zA-Z0-9_-]\\.?)*$");
    return regex_match(s,r);
  }
  shared_ptr<cond> copy() const
  {
    return shared_ptr<cond>(new HostName);
  }
};


struct Numeric : public cond
{
  bool operator()(const string& s) const
  {
    if(s.empty())
      return false;

    for(decl(i,s.begin());i!=s.end();++i)
      if(!isdigit(*i))
	return false;
    return true;
  }
  shared_ptr<cond> copy() const
  {
    return shared_ptr<cond>(new Numeric);
  }
};

struct Switch : public cond
{
  bool operator()(const string& s) const
  {
    return (s=="on" || s=="off");
  }
  shared_ptr<cond> copy() const
  {
    return shared_ptr<cond>(new Switch);
  }
};




struct And : public cond
{
  And(const cond& A, const cond& B)
    : d_A(A.copy()), d_B(B.copy())
  {
  }

  bool operator()(const string& s) const
  {
    return (*d_A)(s) && (*d_B)(s);
  }

  shared_ptr<cond> copy() const
  {
    return shared_ptr<cond>(new And(*d_A, *d_B));
  }
  shared_ptr<cond> d_A, d_B;

};


struct Or : public cond
{
  Or(const cond& A, const cond& B)
    : d_A(A.copy()), d_B(B.copy())
  {
  }


  bool operator()(const string& s) const
  {
    return (*d_A)(s) || (*d_B)(s);
  }

  shared_ptr<cond> copy() const
  {
    return shared_ptr<cond>(new Or(*d_A, *d_B));
  }
  shared_ptr<cond> d_A, d_B;
};

struct Not : public cond
{
  Not(const cond& A)
    : d_A(A.copy())
  {
  }


  bool operator()(const string& s) const
  {
    return !(*d_A)(s);
  }

  shared_ptr<cond> copy() const
  {
    return shared_ptr<cond>(new Not(*d_A));
  }
  shared_ptr<cond> d_A;
};


const Not operator!(const cond &A)
{
  return Not(A);
}

const And operator&&(const cond &A, const cond& B)
{
  return And(A,B);
}

const Or operator||(const cond &A, const cond& B)
{
  return Or(A,B);
}




struct Argument
{
  Argument()
  {}

  Argument(const cond& c, const string& val="") 
    : d_c(c.copy()), d_value(val)
  {}

  shared_ptr<cond> d_c;
  string d_value;
};

typedef runtime_error argument_exception;

class ArgTng
{
public:
  void add(const string &name, const cond& c=Ok(), const string& def="")
  {
    d_content[name]=Argument(c,def);
  }
  
  void constraints() 
  {
    for(decl(i,d_content.begin());i!=d_content.end();++i)
      if(!correct(i->first))
	throw runtime_error("variable '"+i->first+"' violates constraints with value '"+i->second.d_value+"'");
    
  }

  void parse(int argc, char **argv)
  {
    for(int n=1;n<argc;++n)
      parseString(argv[n]);
  }

  const string get(const string& var)
  {
    if(!d_content.count(var))
      throw(runtime_error("trying to read unknown parameter '"+var+"'"));
    return d_content[var].d_value;
  }
  int getInt(const string& var)
  {
    if(!d_content.count(var))
      throw(runtime_error("trying to read unknown parameter '"+var+"'"));
    string val=d_content[var].d_value;
    if(!Numeric()(val))
      throw(runtime_error("trying to convert '"+var+"' value '"+val+"' into a number"));
    return atoi(val.c_str());
  }

private:
  map<string, Argument> d_content;
  bool correct(const string& s)
  {
    return (*d_content[s].d_c)(d_content[s].d_value);
  }
  void parseString(const string& s)
  {
    static const regex r("^--([a-z0-9-]*)=(.*)$");
    match_results<string::const_iterator> res;
    if(!regex_match(s,res,r))
      throw argument_exception("argument item does not match, should be --var=val");

    string var(res[1].first, res[1].second);
    string val(res[2].first, res[2].second);

    if(!d_content.count(var))
      throw argument_exception("trying to set unknown variable '"+var+"'");
    if(!(*d_content[var].d_c)(val))
      throw argument_exception("trying to set variable '"+var+"' to illegal value '"+val+"'");

    d_content[var].d_value=val;
  }
};

#if 0

int main(int argc, char**argv)
try {
  ArgTng at;
  at.add("host", !Empty() && (IpAddress() || HostName()),"localhost");
  at.add("number", Numeric());
  at.parse(argc, argv);
  at.constraints();

  cout<<"Hostname="<<at.get("host")<<endl;
  cout<<"number="<<at.getInt("number")<<endl;

}
catch(argument_exception &ae)
{
  cerr<<"Fatal: "<<ae.what()<<endl;
}
#endif
