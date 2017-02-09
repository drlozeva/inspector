require 'ffi/pcap'
require 'yaml'
require_relative 'rule_matcher'

module Inspector
  class Inspector
    def initialize(rules_file:, output_file:)
      @rules = load_rules(rules_file)
      @output_file = File.open(output_file, "w")
      @output_file.puts "#{Time.now.strftime("%Y-%m-%d %H:%M:%S")}"
    end

    def parse(path)
      cap = FFI::Pcap::Offline.new(path)

      cap.loop do |_, pkt|
        bytes = pkt.body.each_byte.to_a


        @rules.each do |rule|
          if match_rule?(bytes, rule)
            src_ip = bytes[26..29].map { |b| format("%d", b) }.join(".")
            dst_ip = bytes[30..33].map { |b| format("%d", b) }.join(".")
            @output_file.puts("Rule #{rule['name']} match on packet with #{src_ip} -> #{dst_ip}")
          end
        end
      end

      @output_file.close
    end

    protected

    def match_rule?(bytes, rule)
      matcher = RuleMatcher.new(bytes, rule)
       results = [matcher.ethertype?, matcher.protocol?, matcher.flags?]
      p results
      return results.all? { |r| r == true }
      # return matcher.ethertype? &&
      #   matcher.protocol? &&
      #   matcher.flags?
    end

    def load_rules(file)
      rules = YAML.load_file(file)
      return rules
    end
  end
end
