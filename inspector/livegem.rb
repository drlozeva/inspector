require 'ffi/pcap'

pcap =
  FFI::PCap::Live.new(:dev => 'wlp2s0',
                      :timeout => 1,
                      :promisc => true,
                      :handler => FFI::PCap::Handler)

Signal.trap("SIGINT") do
  puts "Interrupt..."
  pcap.breakloop
end

pcap.setfilter("icmp")

pcap.loop() do |this,pkt|
  puts "#{pkt.time}:"

  pkt.body.each_byte {|x| print "%0.2x " % x }
  putc "\n"
end
