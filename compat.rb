#!/usr/bin/env ruby
# -*- coding: utf-8 -*-
#
# Cover Ruby 1.8/1.9 compatibility for TwiProwl
#
# Copyright (c) 2010 Takuo Kitame.
#
# You can redistribute it and/or modify it under the same term as Ruby.
#
begin
  require 'oauth'
rescue LoadError
  require 'rubygems'
  require 'oauth'
end
require 'hmac'

# define Process.daemon (ruby 1.9 feature)
unless Process.respond_to?(:daemon)
  def Process.daemon(nochdir = nil, noclose = nil)
    exit!(0) if fork
    Process.setsid
    Dir.chdir('/') unless nochdir
    unless noclose
      STDIN.reopen('/dev/null')  unless STDIN.closed?
      STDOUT.reopen('/dev/null') unless STDOUT.closed?
      STDERR.reopen('/dev/null') unless STDERR.closed?
    end
    0
  end
end

# implemented for Streamin API
module Net
  class HTTPResponse
    def each_line( rs = "\n" )
      stream_check
      while line = @socket.readuntil( rs )
        yield line
      end
      self
    end
  end
end

# oAuth fix for >= 1.9.0
if RUBY_VERSION >= "1.9.0" and HMAC::VERSION < "0.4.0"
  module HMAC
    class Base
      def set_key(key)
        key = @algorithm.digest(key) if key.size > @block_size
        key_xor_ipad = Array.new(@block_size, 0x36)
        key_xor_opad = Array.new(@block_size, 0x5c)
        key.bytes.each_with_index do |value, index|
          key_xor_ipad[index] ^= value
          key_xor_opad[index] ^= value
        end
        @key_xor_ipad = key_xor_ipad.pack('c*')
        @key_xor_opad = key_xor_opad.pack('c*')
        @md = @algorithm.new
        @initialized = true
      end
    end
  end
end
