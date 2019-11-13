#include "statnode.hh"

StatNode::Stat StatNode::print(unsigned int depth, Stat newstat, bool silent) const
{
  if(!silent) {
    cout<<string(depth, ' ');
    cout<<name<<": "<<endl;
  }
  Stat childstat;
  childstat.queries += s.queries;
  childstat.noerrors += s.noerrors;
  childstat.nxdomains += s.nxdomains;
  childstat.servfails += s.servfails;
  childstat.drops += s.drops;
  childstat.bytes += s.bytes;

  if(children.size()>1024 && !silent) {
    cout<<string(depth, ' ')<<name<<": too many to print"<<endl;
  }
  for(const children_t::value_type& child :  children) {
    childstat=child.second.print(depth+8, childstat, silent || children.size()>1024);
  }
  if(!silent || children.size()>1)
    cout<<string(depth, ' ')<<childstat.queries<<" queries, " << 
      childstat.noerrors<<" noerrors, "<< 
      childstat.nxdomains<<" nxdomains, "<< 
      childstat.servfails<<" servfails, "<< 
      childstat.drops<<" drops, "<<
      childstat.bytes<<" bytes"<<endl;

  newstat+=childstat;

  return newstat;
}


void  StatNode::visit(visitor_t visitor, Stat &newstat, unsigned int depth) const
{
  Stat childstat;
  childstat.queries += s.queries;
  childstat.noerrors += s.noerrors;
  childstat.nxdomains += s.nxdomains;
  childstat.servfails += s.servfails;
  childstat.drops += s.drops;
  childstat.bytes += s.bytes;
  childstat.remotes = s.remotes;
  
  Stat selfstat(childstat);

  for(const children_t::value_type& child :  children) {
    child.second.visit(visitor, childstat, depth+8);
  }

  visitor(this, selfstat, childstat);

  newstat+=childstat;
}


void StatNode::submit(const DNSName& domain, int rcode, unsigned int bytes, boost::optional<const ComboAddress&> remote)
{
  //  cerr<<"FIRST submit called on '"<<domain<<"'"<<endl;
  std::vector<string> tmp = domain.getRawLabels();
  if(tmp.empty())
    return;

  auto last = tmp.end() - 1;
  children[*last].submit(last, tmp.begin(), "", rcode, bytes, remote, 1);
}

/* www.powerdns.com. -> 
   .                 <- fullnames
   com.
   powerdns.com
   www.powerdns.com. 
*/

void StatNode::submit(std::vector<string>::const_iterator end, std::vector<string>::const_iterator begin, const std::string& domain, int rcode, unsigned int bytes, boost::optional<const ComboAddress&> remote, unsigned int count)
{
  //  cerr<<"Submit called for domain='"<<domain<<"': ";
  //  for(const std::string& n :  labels) 
  //    cerr<<n<<".";
  //  cerr<<endl;
  if(name.empty()) {

    name=*end;
    //    cerr<<"Set short name to '"<<name<<"'"<<endl;
  }
  else {
    //    cerr<<"Short name was already set to '"<<name<<"'"<<endl;
  }

  if(end == begin) {
    if (fullname.empty()) {
      fullname=name+"."+domain;
      labelsCount = count;
    }
    //    cerr<<"Hit the end, set our fullname to '"<<fullname<<"'"<<endl<<endl;
    s.queries++;
    s.bytes += bytes;
    if(rcode<0)
      s.drops++;
    else if(rcode==0)
      s.noerrors++;
    else if(rcode==2)
      s.servfails++;
    else if(rcode==3)
      s.nxdomains++;

    if (remote) {
      s.remotes[*remote]++;
    }
  }
  else {
    if (fullname.empty()) {
      fullname=name+"."+domain;
      labelsCount = count;
    }
    //    cerr<<"Not yet end, set our fullname to '"<<fullname<<"', recursing"<<endl;
    --end;
    children[*end].submit(end, begin, fullname, rcode, bytes, remote, count+1);
  }
}

