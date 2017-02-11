require 'rspec'
require 'pathname'
require 'fileutils'
require 'ffi/pcap'

root_dir = Pathname.new(__FILE__).dirname.dirname.dirname
input_file = root_dir.join('spec', 'input', 'xmas1.pcap')
input_file2 = root_dir.join('spec', 'input', 'rst-ack1.pcap')
input_file3 = root_dir.join('spec', 'input', 'xmas2.pcap')
input_file4 = root_dir.join('spec', 'input', 'null1.pcap')
require root_dir.join('inspector/ip_header.rb')

cap = FFI::Pcap::Offline.new(input_file)
cap2 = FFI::Pcap::Offline.new(input_file2)
cap3 = FFI::Pcap::Offline.new(input_file3)
cap4 = FFI::Pcap::Offline.new(input_file4)

checksum = nil
checksum2 = nil
checksum3 = nil
checksum4 = nil

cap.loop do |_, pkt|
  bytes = pkt.body.each_byte.to_a
  checksum = Inspector::IpHeader.check_sum_header(bytes)
end

cap2.loop do |_, pkt|
  bytes = pkt.body.each_byte.to_a
  checksum2 = Inspector::IpHeader.check_sum_header(bytes)
end

cap3.loop do |_, pkt|
  bytes = pkt.body.each_byte.to_a
  checksum3 = Inspector::IpHeader.check_sum_header(bytes)
end

cap4.loop do |_, pkt|
  bytes = pkt.body.each_byte.to_a
  checksum4 = Inspector::IpHeader.check_sum_header(bytes)
end

RSpec.describe('IpHeader') do
  it 'reads the IP header checksum' do
    expect(checksum).to eq('7f91')
    expect(checksum2).to eq('648b')
    expect(checksum3).to eq('6630')
    expect(checksum4).to eq('f89f')
  end

  it 'does not equal to the wrong IP header checksum' do
    expect(checksum).to_not eq('7f61')
    expect(checksum2).to_not eq('7ff1')
    expect(checksum2).to_not eq('6630')
    expect(checksum2).to_not eq('64b8')
    expect(checksum3).to_not eq('6638')
    expect(checksum3).to_not eq('6629')
    expect(checksum4).to_not eq('8f9f')
    expect(checksum4).to_not eq('f8f9')
  end

  it 'calculates the IP header checksum' do
    cap = FFI::Pcap::Offline.new(input_file)
    checksum = nil

    cap.loop do |_, pkt|
      bytes = pkt.body.each_byte.to_a
      checksum = Inspector::IpHeader.calc_check_sum(bytes)
    end

    expect(checksum).to eq(0)
    expect(checksum2).to_not eq(0)
    expect(checksum3).to_not eq(0)
    expect(checksum4).to_not eq(0)
  end
end
