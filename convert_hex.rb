#!/usr/bin/env ruby
require 'optparse'
little_endian = true
depth = 0
OptionParser.new {|o|
  o.on("-l") { little_endian = true }
  o.on("-b") { little_endian = false }
  o.on("-d VAL") {|v| depth = Integer(v) }
  o.parse!(ARGV)
}

def checksum(bytes)
  (256 - (bytes.inject {|r,i| r+i } & 0xff)) & 0xff
end

memory = []
STDIN.each {|line|
  line.chomp!
  next if !(line =~ /^:([0-9a-f]{8})([0-9a-f]{2,})$/i)
  size = ($1.hex >> 24) & 0xff
  addr = ($1.hex >> 8) & 0xffff
  type = ($1.hex) & 0xff
  data = $2
  break if type == 1
  bytes = []
  data.gsub(/../) {|v| bytes << v.hex }
  memory += bytes.pack("C*").unpack(little_endian ? "V*" : "N*")
}
puts ":020000020000FC"
memory.each_index {|i|
  bytes = [4, (i >> 8) & 0xff, i & 0xff, 0]
  bytes += [memory[i]].pack("N").unpack("C*")
  bytes << checksum(bytes)
  puts ":#{bytes.map {|v| "%02X" % v }.join("")}"
}
if(depth > 0 and memory.size > depth)
  STDERR.puts "warning: Memory depth (%d) exceeds maximum memory depth (%d)" % [memory.size, depth]
end
(memory.size...depth).each {|i|
  bytes = [4, (i >> 8) & 0xff, i & 0xff, 0, 0, 0, 0, 0]
  bytes << checksum(bytes)
  puts ":#{bytes.map {|v| "%02X" % v }.join("")}"
}
puts ":00000001FF"
