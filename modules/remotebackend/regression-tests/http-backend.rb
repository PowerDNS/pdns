#!/usr/bin/env ruby
require "rubygems"
require 'bundler/setup'
require "webrick"
$:.unshift File.dirname(__FILE__)
require "dnsbackend"
require "backend"
require "pathname"

server = WEBrick::HTTPServer.new(
	:Port=>62434,
	:BindAddress=>"localhost",
#	Logger: WEBrick::Log.new("remotebackend-server.log"),
	:AccessLog=>[ [ File.open("remotebackend-access.log", "w"), WEBrick::AccessLog::COMBINED_LOG_FORMAT ] ] 
)

be = Handler.new(Pathname.new(File.join(File.dirname(__FILE__),"remote.sqlite3")).realpath.to_s)
server.mount "/dns", DNSBackendHandler, be
server.mount_proc("/ping"){ |req,resp| resp.body = "pong" }

trap('INT') { server.stop }
trap('TERM') { server.stop }

server.start
