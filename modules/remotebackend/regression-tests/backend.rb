#!/usr/bin/ruby1.9.1

require 'json'
require 'sqlite3'

def rr(qname, qtype, content, ttl, priority = 0, auth = 1, domain_id = -1)
   {:qname => qname, :qtype => qtype, :content => content, :ttl => ttl.to_i, :priority => priority.to_i, :auth => auth.to_i, :domain_id => domain_id.to_i}
end

class Handler
   attr :db
 
   def initialize(dbpath)
     @db = SQLite3::Database.new dbpath
   end

   def do_initialize(*args)
     return true, "Test bench initialized"
   end

   def do_getbeforeandafternamesabsolute(args)
        before = @db.get_first_value("SELECT ordername FROM records WHERE ordername < ? AND domain_id = ?", args["qname"], args["id"])
        after = @db.get_first_value("SELECT ordername FROM records WHERE ordername > ? AND domain_id = ?", args["qname"], args["id"])
        return [{:before => before, :after => after, :unhashed => args["qname"]}, nil]
   end

   def do_getbeforeandafternames(args)
        before = @db.get_first_value("SELECT ordername FROM records WHERE ordername < ? AND domain_id = ?", args["qname"], args["id"])
        after = @db.get_first_value("SELECT ordername FROM records WHERE ordername > ? AND domain_id = ?", args["qname"], args["id"])
        return [{:before => before, :after => after, :unhashed => args["qname"]}, nil]
   end

   def do_getdomainkeys(args)
       ret = []
       @db.execute("SELECT flags,active,content FROM domains JOIN cryptokeys ON domains.id = cryptokeys.domain_id WHERE domains.name = ?", args["name"]) do |row|
          ret << {:flags => row[0].to_i, :active => !(row[1].to_i.zero?), :content => row[2]}
       end 

       return false if ret.empty?
       return [ret,nil]
   end

   def do_lookup(args)
     ret = []
     loop do
        begin
          sargs = {}
          if (args["qtype"] == "ANY")
             sql = "SELECT domain_id,name,type,content,ttl,prio,auth FROM records WHERE name = :qname"
             sargs["qname"] = args["qname"]
          else
             sql = "SELECT domain_id,name,type,content,ttl,prio,auth FROM records WHERE name = :qname AND type = :qtype"
             sargs["qname"] = args["qname"]
             sargs["qtype"] = args["qtype"]
          end
          db.execute(sql, sargs) do |row|
            ret << rr(row[1], row[2], row[3], row[4], row[5], row[6], row[0])
          end
        rescue Exception => e
          e.backtrace
        end
        break
     end
     return false unless ret.size > 0
     return [ret,nil]
   end
 
   def do_list(args)
     target = args["target"]
     ret = []
     loop do
        begin
          d_id = db.get_first_value("SELECT id FROM domains WHERE name = ?", target)
          return false if d_id.nil?
          db.execute("SELECT domain_id,name,type,content,ttl,prio,auth FROM records WHERE domain_id = ?", d_id) do |row|
            ret << rr(row[1], row[2], row[3], row[4], row[5], row[6], row[0])
          end
        rescue Exception => e
          e.backtrace
        end
        break
     end
     return false unless ret.size > 0
     return [ret,nil]
   end

   def do_getdomainmetadata(args) 
	return false
   end

   def do_setdomainmetadata(args)
	return false
   end
end
