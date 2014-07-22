#!/usr/bin/env ruby

require 'rubygems'
require 'bundler/setup'
require 'json'
require 'zero_mq'
require './unittest'

h = Handler.new()
f = File.open "/tmp/remotebackend.txt.#{$$}","a"
f.sync = true

runcond=true

trap('INT') { runcond = false }
trap('TERM') { runcond = false }

begin
  context = ZeroMQ::Context.new
  socket = context.socket ZMQ::REP
  socket.bind("ipc:///tmp/remotebackend.0")
 
  print "[#{Time.now.to_s}] ZeroMQ unit test responder running\n"

  while(runcond) do
    line = ""
    rc = socket.recv_string line
    # expect json
    input = {}
    line = line.strip

    f.puts "#{Time.now.to_f}: [zmq] #{line}"
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
      socket.send_string ({:result => res, :log => log}).to_json + "\n" , 0
      f.puts "#{Time.now.to_f} [zmq]: #{({:result => res, :log => log}).to_json}"
    rescue JSON::ParserError
      socket.send_string ({:result => false, :log => "Cannot parse input #{line}"}).to_json + "\n";
      f.puts "#{Time.now.to_f} [zmq]: #{({:result => false, :log => "Cannot parse input #{line}"}).to_json}"
      next
    end
  end
rescue SystemExit, Interrupt, Errno::EINTR
end

print "[#{Time.now.to_s}] ZeroMQ unit test responder ended\n"
