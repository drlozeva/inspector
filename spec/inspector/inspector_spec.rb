RSpec.describe('NetSec') do
  it 'detects christmas packets' do
    listener = NetSec.new(rules_file: project_root_dir.join('example', 'rules_xmas.yml'), output_dir: '..../spec/output')
    listener.parse('.../spec/input_data/christmas_tree.pcap'),

    output = File.read('.../spec/output/2017-02-05....txt')

    expect(output).to include("Christmas tree detected ...")
  end

  it 'detects null packets' do
    listener = NetSec.new(rules_file: '.../spec/rules/null_packets.yml', output_dir: '..../spec/output')
    listener.parse('.../spec/input_data/null_packets.pcap')

    output = File.read('.../spec/output/2017-02-05....txt')

    expect(output).to include("Null packet detected ....")
  end

end

