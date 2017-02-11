require 'rspec'
require 'pathname'
require 'fileutils'
require 'ffi/pcap'

root_dir = Pathname.new(__FILE__).dirname.dirname.dirname
input_file = root_dir.join('spec', 'input', 'xmas1.pcap')

require root_dir.join('inspector/ip_header.rb')

RSpec.describe('IpHeader') do
  it 'reads the IP header checksum' do
    cap = FFI::Pcap::Offline.new(input_file)
    checksum = nil

    cap.loop do |_, pkt|
      bytes = pkt.body.each_byte.to_a
      checksum = Inspector::IpHeader.check_sum_header(bytes)
    end

    expect(checksum).to eq('7f91')
  end

  it 'calculates the IP header checksum' do
    cap = FFI::Pcap::Offline.new(input_file)
    checksum = nil

    cap.loop do |_, pkt|
      bytes = pkt.body.each_byte.to_a
      checksum = Inspector::IpHeader.calc_check_sum(bytes)
    end

    expect(checksum).to eq(0)
  end
end
