#!/usr/bin/env ruby

require 'rubygems'
require 'json'
require 'sqlite3'

def rr(qname, qtype, content, ttl, auth = 1, domain_id = -1)
   {:qname => qname, :qtype => qtype, :content => content, :ttl => ttl.to_i, :auth => auth.to_i, :domain_id => domain_id.to_i}
end

class Handler
   def initialize(dbpath)
     @dbpath = dbpath
     @db = SQLite3::Database.new @dbpath
   end

   def db
      if block_given?
        @db.transaction
        begin
           yield @db
        rescue
           @db.rollback
           return
         end
         @db.commit
      else
         @db
      end
   end

   def do_initialize(*args)
     return true, "Test bench initialized"
   end

   def getbeforename(qname, id)
        before = db.get_first_value("SELECT ordername FROM records WHERE ordername < ? AND domain_id = ? ORDER BY ordername DESC", qname, id)
        if (before.nil?) 
           before = db.get_first_value("SELECT ordername FROM records WHERE domain_id = ? ORDER by ordername DESC LIMIT 1", id)
        end
        before
   end

  def getaftername(qname, id)
        after = db.get_first_value("SELECT ordername FROM records WHERE ordername > ? AND domain_id = ? ORDER BY ordername", qname, id)
        if (after.nil?)
           after = db.get_first_value("SELECT ordername FROM records WHERE domain_id = ? ORDER by ordername LIMIT 1", id)
        end
        after
   end


   def do_getbeforeandafternamesabsolute(args)
        args["qname"] = "" if args["qname"].nil?
        return [{:before => getbeforename(args["qname"],args["id"]), :after => getaftername(args["qname"],args["id"]), :unhashed => args["qname"]}, nil]
   end

   def do_getbeforeandafternames(args)
        args["qname"] = "" if args["qname"].nil?
        return [{:before => getbeforename(args["qname"],args["id"]), :after => getaftername(args["qname"],args["id"]), :unhashed => args["qname"]}, nil]
   end

   def do_getdomainkeys(args)
       ret = []
       db.execute("SELECT cryptokeys.id,flags,active, published, content FROM domains JOIN cryptokeys ON domains.id = cryptokeys.domain_id WHERE domains.name = ?", [args["name"]]) do |row|
          ret << {:id => row[0].to_i, :flags => row[1].to_i, :active => !(row[2].to_i.zero?), :published => row[3], :content => row[4]}
       end 
       return false if ret.empty?
       return [ret,nil]
   end

   def do_lookup(args)
     ret = []
     loop do
        begin
          sargs = {}
          if (args["zone-id"].to_i > 0)
             sargs["domain_id"] = args["zone-id"].to_i
             if (args["qtype"] == "ANY")
                sql = "SELECT domain_id,name,type,content,ttl,prio,auth FROM records WHERE name = :qname AND domain_id = :domain_id"
                sargs["qname"] = args["qname"]
             else
                sql = "SELECT domain_id,name,type,content,ttl,prio,auth FROM records WHERE name = :qname AND type = :qtype AND domain_id = :domain_id"
                sargs["qname"] = args["qname"]
                sargs["qtype"] = args["qtype"]
             end
          else
             if (args["qtype"] == "ANY")
                sql = "SELECT domain_id,name,type,content,ttl,prio,auth FROM records WHERE name = :qname"
                sargs["qname"] = args["qname"]
             else
                sql = "SELECT domain_id,name,type,content,ttl,prio,auth FROM records WHERE name = :qname AND type = :qtype"
                sargs["qname"] = args["qname"]
                sargs["qtype"] = args["qtype"]
             end  
          end
          db.execute(sql, sargs) do |row|
            if (row[2] == "MX" || row[2] == "SRV")
              ret << rr(row[1], row[2], row[5]+" "+row[3], row[4], row[6], row[0])
            else
              ret << rr(row[1], row[2], row[3], row[4], row[6], row[0])
            end
          end
        rescue Exception => e
          e.backtrace
          return false, [e.message]
        end
        break
     end
     return false unless ret.size > 0
     return [ret,nil]
   end
  
   def do_getdomaininfo(args) 
     ret = {}
     sql = "SELECT name,content FROM records WHERE name = :name AND type = 'SOA'"
     db.execute(sql, args) do |row|
       ret[:zone] = row[0]
       ret[:serial] = row[1].split(' ')[2].to_i
       ret[:kind] = "native"
     end
     return [ret,nil] if ret.has_key?(:zone)
     return false
   end

   def do_list(args)
     target = args["zonename"]
     ret = []
     loop do
        begin
          d_id = db.get_first_value("SELECT id FROM domains WHERE name = ?", target)
          return false if d_id.nil?
          db.execute("SELECT domain_id,name,type,content,ttl,prio,auth FROM records WHERE domain_id = ?", d_id) do |row|
            if (row[2] == "MX" || row[2] == "SRV")
              ret << rr(row[1], row[2], row[5]+" "+row[3], row[4], row[6], row[0])
            else
              ret << rr(row[1], row[2], row[3], row[4], row[6], row[0])
            end
          end
        rescue Exception => e
          e.backtrace
          return false, [e.message]
        end
        break
     end
     return false unless ret.size > 0
     return [ret,nil]
   end

   def do_adddomainkey(args)
     d_id = db.get_first_value("SELECT id FROM domains WHERE name = ?", args["name"])
     return false if d_id.nil?
     sql = "INSERT INTO cryptokeys (domain_id, flags, active, published, content) VALUES(?,?,?,?,?)"
     active = args["key"]["active"]
     if (active) 
        active = 1
     else
        active = 0
     end
     published = args["key"]["published"]
     if (published)
         published = 1
     else
         published = 0
     end
     db do |tx|
        tx.execute(sql, [d_id, args["key"]["flags"].to_i, active, published, args["key"]["content"]])
     end
     return db.get_first_value("SELECT last_insert_rowid()").to_i
   end

   def do_deactivatedomainkey(args)
     d_id = db.get_first_value("SELECT id FROM domains WHERE name = ?", args["name"])
     return false if d_id.nil?
     db do |tx|
       tx.execute("UPDATE cryptokeys SET active = 0 WHERE domain_id = ? AND id = ?", [d_id, args["id"]])  
     end
     return true
   end

   def do_activatedomainkey(args)
     d_id = db.get_first_value("SELECT id FROM domains WHERE name = ?", args["name"])
     return false if d_id.nil?
     db do |tx|
       db.execute("UPDATE cryptokeys SET active = 1 WHERE domain_id = ? AND id = ?", [d_id, args["id"]])
     end
     return true
   end

   def do_unpublishdomainkey(args)
     d_id = db.get_first_value("SELECT id FROM domains WHERE name = ?", args["name"])
     return false if d_id.nil?
     db do |tx|
       tx.execute("UPDATE cryptokeys SET published = 0 WHERE domain_id = ? AND id = ?", [d_id, args["id"]])
     end
     return true
   end

   def do_publishdomainkey(args)
     d_id = db.get_first_value("SELECT id FROM domains WHERE name = ?", args["name"])
     return false if d_id.nil?
     db do |tx|
       db.execute("UPDATE cryptokeys SET published = 1 WHERE domain_id = ? AND id = ?", [d_id, args["id"]])
     end
     return true
   end

   def do_getdomainmetadata(args) 
	ret = []
        sql = "SELECT content FROM domainmetadata JOIN domains WHERE name = :name AND kind = :kind"
        sargs = {:name => args["name"], :kind => args["kind"]}
        db.execute(sql,sargs) do |row|
          ret << row[0]
        end
        return false unless ret.size > 0
        return [ret,nil]
   end

   def do_setdomainmetadata(args)
        d_id = db.get_first_value("SELECT id FROM domains WHERE name = ?", args["name"])
        return false if d_id.nil?
        db do |tx|
           sql = "DELETE FROM domainmetadata WHERE domain_id = ? AND kind = ?"
           tx.execute(sql, [d_id, args["kind"]])
           unless args["value"].nil?
             sql = "INSERT INTO domainmetadata (domain_id,kind,content) VALUES(?,?,?)"
             args["value"].each do |value|
               STDERR.puts"Executing INSERT INTO domainmetadata (domain_id,kind,content) VALUES(#{d_id}, #{args["kind"]}, #{value})"
               tx.execute(sql,[d_id, args["kind"], value])
             end
           end
        end
	return true
   end

   def do_directbackendcmd(args)
     return [args["query"]]
   end
end
