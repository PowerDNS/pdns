#!/usr/bin/env ruby

require 'rubygems'
require 'bundler/setup'
require 'json'
require './unittest'

h = Handler.new()
f = File.open "/tmp/remotebackend.txt.#{$$}","a"
f.sync

STDOUT.sync = true
begin
  STDIN.each_line do |line|
    f.puts "#{Time.now.to_f}: [pipe] #{line}"
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
      puts ({:result => res, :log => log}).to_json
      f.puts "#{Time.now.to_f} [pipe]: #{({:result => res, :log => log}).to_json}"
    rescue JSON::ParserError
      puts ({:result => false, :log => "Cannot parse input #{line}"}).to_json
      f.puts "#{Time.now.to_f} [pipe]: #{({:result => false, :log => "Cannot parse input #{line}"}).to_json}"
      next
    end
  end
rescue SystemExit, Interrupt
end
