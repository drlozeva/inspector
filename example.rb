require_relative './inspector/inspector'
require 'pry-byebug'

puts 'Program started.'

project_root_dir = Pathname.new(__FILE__).dirname

listener = Inspector::Inspector.new(
  rules_file: project_root_dir.join('example', 'rules_xmas.yml'),
  output_file: project_root_dir.join('example', 'output', 'output_file.txt')
)

# Read from file
listener.parse(project_root_dir.join('example', 'input', 'test.pcap'))

# # Live
# listener.listen('lo0')

puts 'Program finished.'
