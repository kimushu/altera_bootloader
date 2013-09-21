#!/usr/bin/env ruby
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
  memory += bytes.pack("C*").unpack("V*")
}
puts ":020000020000FC"
memory.each_index {|addr|
  bytes = [4, (addr >> 8) & 0xff, addr & 0xff, 0]
  bytes += [memory[addr]].pack("N").unpack("C*")
  bytes << ((256 - (bytes.inject {|r,i| r+i } & 0xff)) & 0xff)
  puts ":#{bytes.map {|v| "%02X" % v }.join("")}"
}
puts ":00000001FF"
