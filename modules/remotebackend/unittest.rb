require 'rubygems'
require 'bundler/setup'
require 'json'

# define a simple $domain

$ttl = 300
$notified_serial = 1

$domain = {
  "unit.test." => { 
      "SOA" => ["ns.unit.test. hostmaster.unit.test. 1 2 3 4 5"],
      "NS" => ["ns1.unit.test.", "ns2.unit.test."],
  },
  "ns1.unit.test." => {
       "A" => ["10.0.0.1"]
  },
  "ns2.unit.test." => {
       "A" => ["10.0.0.2"]
  }, 
  "empty.unit.test." => {}
}

$meta = {}

$keys = {}

$tsigkeys = { "test." => {:name => "test.", :algorithm => "NULL.", :content => "NULL"} }

$masters = { :name => "ns1.unit.test.", :ip => "10.0.0.1" }

class Handler
   def initialize
   end

   def rr(qname, qtype, content, ttl, auth = 1, domain_id = -1)
      {:qname => qname, :qtype => qtype, :content => content, :ttl => ttl.to_i, :auth => auth.to_i, :domain_id => domain_id.to_i}
   end

   def do_initialize(*args)
     return true, "Test bench initialized"
   end

   def do_lookup(args) 
     ret = []
     if $domain.has_key?(args["qname"])
       if $domain[args["qname"]].has_key?(args["qtype"])
         $domain[args["qname"]][args["qtype"]].each do |rd|
            ret << rr(args["qname"], args["qtype"], rd, $ttl)
         end
       elsif args["qtype"] == 'ANY'
         $domain[args["qname"]].each do |qt,qr|
           qr.each do |rd|
             ret << rr(args["qname"], qt, rd, $ttl)
           end
         end
       end
     end
     [false] unless ret.size>0 and args["qname"] != "empty.unit.test"
     [ret]
   end

   def do_list(args)
     ret = []
     if args["zonename"] == "unit.test."
       $domain.each do |qname,rdata| 
         rdata.each do |rtype,rc|
          rc.each do |rd|
            ret << rr(qname,rtype,rd,$ttl)
          end
         end
        end
     end
     [false] unless ret.size>0
     [ret]
   end 

   def do_getalldomainmetadata(args)
     return [ $meta[args["name"]] ] if $meta.has_key?(args["name"])
     return [false]
   end

   def do_getdomainmetadata(args)
     return [ $meta[args["name"]][args["kind"]] ] if $meta.has_key?(args["name"]) and $meta[args["name"]].has_key?(args["kind"])
     return [false]
   end

   def do_setdomainmetadata(args)
     $meta[args["name"].to_s] = {} unless $meta.has_key? args["name"]
     $meta[args["name"].to_s][args["kind"].to_s] = args["value"].to_a
     [true]
   end

   def do_adddomainkey(args)
     $keys[args["name"]] = [] unless $keys.has_key? args["name"]
     id=$keys[args["name"]].size + 1
     args["key"]["id"] = id
     $keys[args["name"]] << args["key"]
     [id]
   end

   def do_getdomainkeys(args) 
     if $keys.has_key? args["name"]
       return [ $keys[args["name"]] ]
     end
     [false]
   end 

   def do_activatedomainkey(args) 
     args["id"] = args["id"].to_i
     if $keys.has_key? args["name"]
      if $keys[args["name"]][args["id"]-1]
         $keys[args["name"]][args["id"]-1]["active"] = true
         return [true]
      end
     end
     [false]
   end 

   def do_deactivatedomainkey(args)
     args["id"] = args["id"].to_i
     if $keys.has_key? args["name"]
      if $keys[args["name"]][args["id"]-1]
         $keys[args["name"]][args["id"]-1]["active"] = false
         return [true]
      end
     end
     [false]
   end

   def do_removedomainkey(args)
     args["id"] = args["id"].to_i
     if $keys.has_key? args["name"]
      if $keys[args["name"]][args["id"]-1]
       $keys[args["name"]].delete_at args["id"]-1
       return [true]
      end
     end
     [false]
   end 

   def do_getbeforeandafternamesabsolute(args)
     return [ { :unhashed => "middle.", :before => "begin.", :after => "stop." } ] if args["qname"] == 'middle.unit.test.'
     [false]
   end

   def do_gettsigkey(args) 
     if $tsigkeys.has_key? args["name"]
       return [{:algorithm => $tsigkeys[args["name"]][:algorithm], :content => $tsigkeys[args["name"]][:content] }]
     end
     [false] 
   end

   def do_setnotified(args) 
     if args["id"].to_i == 1 
       $notified_serial = args["serial"].to_i
       return [true]
     end
     [false]
   end

   def do_getdomaininfo(args) 
     if args["name"] == "unit.test."
       return [{ 
               :id => 1,
               :zone => "unit.test.",
               :masters => ["10.0.0.1"],
               :notified_serial => $notified_serial,
               :serial => $notified_serial, 
               :last_check => Time.now.to_i,
               :kind => 'native'
       }]
     end
     if args["name"] == "master.test."
       return [{
               :id => 2,
               :zone => "master.test.",
               :masters => ["10.0.0.1"],
               :notified_serial => $notified_serial,
               :serial => $notified_serial,
               :last_check => Time.now.to_i,
               :kind => 'master'
       }]
     end
     [false]
   end

   def do_ismaster(args)
     $masters[:name] == args["name"] && $masters[:ip] == args["ip"]
   end

   def do_supermasterbackend(args) 
     $domain[args["domain"]] = {
        "NS" => args["nsset"]
     }
     [true]
   end

   def do_createslavedomain(args)
     $domain[args["domain"]] = {
     }
     [true]
   end

   def do_feedrecord(args)
      args.delete "trxid"
      rr = args["rr"]
      name = rr["qname"]
      qtype = rr["qtype"]
      $domain[name] = {} unless $domain.has_key? name
      $domain[name][qtype] = [] unless $domain[name].has_key? qtype
      $domain[name][qtype] << rr["content"]
      [true]
   end

   def do_replacerrset(args)
      $domain[args["qname"]].delete args["qtype"] if $domain.has_key?(args["qname"]) and $domain[args["qname"]].has_key?(args["qtype"])
      args["rrset"] = args["rrset"].values if args["rrset"].is_a?(Hash)
      args["rrset"].each do |rr|
        self.do_feedrecord({"trxid" => args["trxid"], "rr" => rr})
      end
      [true]
   end 

   def do_feedents(args)
      [true]
   end

   def do_feedents3(args)
      [true]
   end

   def do_settsigkey(args) 
      $tsigkeys[args["name"]] = { :name => args["name"], :algorithm => args["algorithm"], :content => args["content"] }
      [true]
   end

   def do_deletetsigkey(args)
      $tsigkeys.delete args["name"] if $tsigkeys.has_key? args["name"]
      [true]
   end

   def do_gettsigkeys(*args)
      return [$tsigkeys.values]
   end

   def do_starttransaction(args) 
     [true]
   end

   def do_committransaction(args)
     [true]
   end

   def do_aborttransaction(args)
     [true]
   end

   def do_directbackendcmd(args)
     [args["query"]]
   end

   def do_getalldomains(args)
     [do_getdomaininfo({'name'=>'unit.test.'})]
   end

   def do_getupdatedmasters()
     [do_getdomaininfo({'name'=>'master.test.'})]
   end
end

