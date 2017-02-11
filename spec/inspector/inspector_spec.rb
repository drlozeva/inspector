require 'rspec'
require 'pathname'
require 'fileutils'

root_dir = Pathname.new(__FILE__).dirname.dirname.dirname
require root_dir.join('inspector/inspector.rb')

RSpec.describe('Inspector') do
  it 'detects christmas packets' do
    rules_file = root_dir.join('spec', 'rules', 'rules_xmas.yml')
    input_file = root_dir.join('spec', 'input', 'christmas_packets.pcap')
    output_file = root_dir.join('spec', 'output', 'christmas_packets.txt')

    FileUtils.rm_f(output_file)
    listener = Inspector::Inspector.new(rules_file: rules_file, output_file: output_file)
    listener.parse(input_file)

    expect(File.exist?(output_file)).to eq(true)

    output = File.read(output_file)

    expect(output).to include(
      'Rule Christmas TCP packets match on packet with 192.168.42.57 -> 192.168.42.187'
    )

    expect(output).not_to include(
      'Rule Christmas TCP packets match on packet with 192.167.42.57 -> 192.168.42.187'
    )
  end

  it 'detects null packets' do
    rules_file = root_dir.join('spec', 'rules', 'rules_null.yml')
    input_file = root_dir.join('spec', 'input', 'christmas_packets.pcap')
    output_file = root_dir.join('spec', 'output', 'christmas_packets.txt')

    FileUtils.rm_f(output_file)
    listener = Inspector::Inspector.new(rules_file: rules_file, output_file: output_file)
    listener.parse(input_file)

    expect(File.exist?(output_file)).to eq(true)

    output = File.read(output_file)

    expect(output).to include(
      'Rule Null TCP packets match on packet with 192.168.42.57 -> 192.168.42.187'
    )

    expect(output).to include(
      'Rule Null TCP packets match on packet with 192.168.42.187 -> 192.168.42.57'
    )

    expect(output).not_to include(
      'Rule Christmas Null packets match on packet with 192.167.42.57 -> 192.168.42.187'
    )

    expect(output).not_to include(
      'Rule Null TCP packets match on packet with 192.168.42.187 -> 192.167.42.57'
    )
  end

  it 'detects SYN packets' do
    rules_file = root_dir.join('spec', 'rules', 'rules_syn.yml')
    input_file = root_dir.join('spec', 'input', 'christmas_packets.pcap')
    output_file = root_dir.join('spec', 'output', 'christmas_packets.txt')

    FileUtils.rm_f(output_file)
    listener = Inspector::Inspector.new(rules_file: rules_file, output_file: output_file)
    listener.parse(input_file)

    expect(File.exist?(output_file)).to eq(true)

    output = File.read(output_file)

    expect(output).to include(
      'Rule TCP SYN scan match on packet with 192.168.42.57 -> 192.168.42.187'
    )

    expect(output).to include(
      'Rule TCP SYN scan match on packet with 192.168.42.187 -> 192.168.42.57'
    )

    expect(output).not_to include(
      'Rule SYN scan match on packet with 192.168.42.187 -> 192.168.42.57'
    )

    expect(output).not_to include(
      'Rule TCP SYN scan match on packet 192.168.42.187 -> 192.168.42.57'
    )
  end
end
