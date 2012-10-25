qname = "node-b.dyn.example.com"

def to32(number)
   number.to_s(32).tr "0123456789abcdefghijklmnopqrstuv", "ybndrfg8ejkmcpqxot1uwisza345h769"
end

def from32(str)
   str.tr("ybndrfg8ejkmcpqxot1uwisza345h769", "0123456789abcdefghijklmnopqrstuv").to_i(32)
end

def rr(qname, qtype, content, ttl, priority = 0, auth = 1)
   {:qname => qname, :qtype => qtype, :content => content, :ttl => ttl, :priority => priority, :auth => auth}
end

def send_result(*params)

end

def main(qname,qtype)
   if qname[/\.?dyn.example.com$/]
    if qname == "dyn.example.com"
      ret = []
      if (qtype != "SOA")
         ret << rr(qname, "NS", "ns1.example.com",300)
         ret << rr(qname, "NS", "ns2.example.com",300)
         ret << rr(qname, "NS", "ns3.example.com",300)
      end
      ret << rr(qname,"SOA","ns1.example.com hostmaster.example.com #{Time.now.strftime("%Y%m%d%H")} 28800 7200 1209600 300",300)
      return send_result ret
    elsif qtype == "ANY" or qtype == "AAAA"
      name = qname.match(/^node-(.*)\.dyn.example.com$/)[1]
      if name.empty?
        return send_result false
      end
#      if name.size < 16
#        pad = 15-name.size
#        (1..pad).each do |i| name = "y#{name}" end
#      end
      puts from32(name)
      return send_result [rr(qname, "AAAA", "", 300)]
    end
   end
   send_result false
end

main qname,"AAAA"
