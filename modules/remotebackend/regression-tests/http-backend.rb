#!/usr/bin/env ruby
require "rubygems"
require 'bundler/setup'
require "webrick"
$:.unshift File.dirname(__FILE__)
require "dnsbackend"
require "backend"

server = WEBrick::HTTPServer.new(
	:Port=>62434,
	:BindAddress=>"localhost",
#	Logger: WEBrick::Log.new("remotebackend-server.log"),
	:AccessLog=>[ [ File.open("remotebackend-access.log", "w"), WEBrick::AccessLog::COMBINED_LOG_FORMAT ] ] 
)

be = Handler.new("#{File.dirname(__FILE__)}/remote.sqlite3")
server.mount "/dns", DNSBackendHandler, be
server.mount_proc("/ping"){ |req,resp| resp.body = "pong" }

trap('INT') { server.stop }
trap('TERM') { server.stop }

server.start
