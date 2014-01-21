#!/usr/bin/env ruby
require "rubygems"
require 'bundler/setup'
require 'json'
$:.unshift File.dirname(__FILE__)
require "backend"

h = Handler.new("#{File.dirname(__FILE__)}/remote.sqlite3")

f = File.open "/tmp/tmp.txt","a"
f.sync = true

STDOUT.sync = true
begin 
  STDIN.each_line do |line|
    f.puts line
    # expect json
    input = {}
    line = line.strip
    next if line.empty?
    begin
      input = JSON.parse(line)
      next unless input and input["method"]
      method = "do_#{input["method"].downcase}"
      args = input["parameters"]

      if h.respond_to?(method.to_sym) == false
         res = false
      elsif args.size > 0
         res, log = h.send(method,args)
      else
         res, log = h.send(method)
      end
      puts ({:result => res, :log => log}).to_json
      f.puts({:result => res, :log => log}).to_json
    rescue JSON::ParserError
      puts ({:result => false, :log => "Cannot parse input #{line}"}).to_json
      next
    end
  end
rescue SystemExit, Interrupt
end
