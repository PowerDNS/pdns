#!/usr/bin/ruby1.9.1

#!/usr/bin/env ruby
require "rubygems"
require 'bundler/setup'
require 'json'
require 'zero_mq'
require '../modules/remotebackend/regression-tests/backend'

h = Handler.new("../modules/remotebackend/regression-tests/remote.sqlite3")

f = File.open "/tmp/tmp.txt","a"

begin
  context = ZeroMQ::Context.new
  socket = context.socket ZMQ::REP
  socket.bind("ipc:///tmp/pdns.0")

  while(true) do
    line = ""
    rc = socket.recv_string line
    f.puts line
    # expect json
    input = {}
    line = line.strip
    next if line.empty?
    begin
      input = JSON.parse(line)
      method = "do_#{input["method"].downcase}"
      args = input["parameters"] || []

      if h.respond_to?(method.to_sym) == false
         res = false
      elsif args.size > 0
         res, log = h.send(method,args)
      else
         res, log = h.send(method)
      end
      socket.send_string ({:result => res, :log => log}).to_json, 0
      f.puts({:result => res, :log => log}).to_json
    rescue JSON::ParserError
      socket.send_string ({:result => false, :log => "Cannot parse input #{line}"}).to_json
      next
    end
  end
rescue SystemExit, Interrupt
end
