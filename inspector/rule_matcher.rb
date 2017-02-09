module Inspector
  class RuleMatcher

    attr_reader :bytes, :rule

    def initialize(bytes, rule)
      @bytes = bytes
      @rule = rule
    end

    def ethertype?
      return false unless rule['layer2']['ethertype']

      case rule['layer2']['ethertype']
      when 'ipv4' then return bytes[12] == 0x08 && bytes[13] == 0x00
      when 'ipv6' then return bytes[12] == 0x09 && bytes[13] == 0x00
      else fail "Unknown ethertype: #{rule['layer2']['ethertype']}"
      end
    end

    def protocol?
      return false unless rule['layer3']['protocol']

      case rule['layer3']['protocol']
      when 'tcp' then return bytes[23] == 0x06
      when 'udp' then return bytes[23] == 0x11
      else fail "Unknown protocol: #{rule['layer3']['protocol']}"
      end
    end

    def flags?
      if rule['layer4']['flags']
        bytes_num = bytes[46..47].reduce("0x") { |a, e| a + format("%x", e) }.to_i(16)
        matched_flags = match_flags
        return bytes_num & matched_flags == matched_flags
      end
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
        else fail "Unknown flag: #{flag}"
        end
      end
      flag_mask
    end
  end
end


