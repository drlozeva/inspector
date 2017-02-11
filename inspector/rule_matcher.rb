module Inspector
  # some comment
  class RuleMatcher
    attr_reader :bytes, :rule

    def initialize(bytes, rule)
      @bytes = bytes
      @rule = rule
    end

    def ethertype?
      return true unless rule['layer2'] && rule['layer2']['ethertype']

      case rule['layer2']['ethertype']
      when 'ipv4' then return bytes[12] == 0x08 && bytes[13].zero?
      when 'ipv6' then return bytes[12] == 0x09 && bytes[13].zero?
      else raise "Unknown ethertype: #{rule['layer2']['ethertype']}"
      end
    end

    def protocol?
      return true unless rule['layer3'] && rule['layer3']['protocol']

      case rule['layer3']['protocol']
      when 'tcp' then return bytes[23] == 0x06
      when 'udp' then return bytes[23] == 0x11
      else raise "Unknown protocol: #{rule['layer3']['protocol']}"
      end
    end

    def flags?
      return true unless rule['layer4'] && rule['layer4']['flags']
      bytes_num = bytes[46..47].reduce('0x') { |acc, elem| acc + format('%x', elem) }.to_i(16)
      matched_flags = match_flags
      bytes_num & matched_flags == matched_flags
    end

    protected

    def match_flags
      flag_mask = 0x00
      rule['layer4']['flags'].each do |flag|
        case flag
        when 'FIN' then flag_mask |= 1
        when 'SYN' then flag_mask |= 2
        when 'RST' then flag_mask |= 4
        when 'PSH' then flag_mask |= 8
        when 'ACK' then flag_mask |= 16
        when 'URG' then flag_mask |= 32
        when 'ECE' then flag_mask |= 64
        when 'CWR' then flag_mask |= 128
        else raise "Unknown flag: #{flag}"
        end
      end
      flag_mask
    end
  end
end
