require 'ffi/pcap'
require 'yaml'
require_relative 'rule_matcher'

module Inspector
  # class Inspector inspects the rules
  class Inspector
    def initialize(rules_file:, output_file:)
      @rules = load_rules(rules_file)
      @output_file = File.open(output_file, 'w')
      @output_file.puts Time.now.to_s
    end

    def parse(path)
      cap = FFI::Pcap::Offline.new(path)

      cap.loop do |_, pkt|
        bytes = pkt.body.each_byte.to_a
        check_rules(bytes)
      end
      @output_file.close
    end

    def check_rules(bytes)
      @rules.each do |rule|
        next unless match_rule?(bytes, rule)
        src_ip = bytes[26..29].map { |b| format('%d', b) }.join('.')
        dst_ip = bytes[30..33].map { |b| format('%d', b) }.join('.')
        @output_file.puts("Rule #{rule['name']} match on packet with #{src_ip} -> #{dst_ip}")
      end
    end

    protected

    def match_rule?(bytes, rule)
      matcher = RuleMatcher.new(bytes, rule)

      matcher.ethertype? &&
        matcher.protocol? &&
        matcher.flags?
    end

    def load_rules(file)
      rules = YAML.load_file(file)
      rules
    end
  end
end
