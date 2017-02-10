require 'ffi/pcap'

pcap =
  FFI::PCap::Live.new(dev: 'lo',
                      timeout: 1,
                      promisc: true,
                      handler: FFI::PCap::Handler)

Signal.trap('SIGINT') do
  puts 'Interrupt...'
  pcap.breakloop
end

pcap.setfilter('icmp')

pcap.loop do |_this, pkt|
  puts "#{pkt.time}:"

  puts pkt.body.each_byte.map { |b| format('%04X', b) }.join('.')
  putc "\n"
end
