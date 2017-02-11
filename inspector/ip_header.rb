module Inspector
  # rubocop is a bitch
  module IpHeader
    module_function

    def check_sum_header(bytes)
      sum = bytes[24..25]
      sum.map { |b| format('%x', b) }.join
    end

    def inspect_num(x)
      hex = format('%04X', x).rjust(5)
      bin = format('%016b', x).rjust(17)
      puts "#{hex} -> #{bin} (#{x})"
    end

    def bin_add(a, b, carry_detector = 2**16)
      sum = a + b
      sum -= (carry_detector - 1) if sum >= carry_detector
      sum
    end

    def calc_check_sum(bytes)
      words = bytes[14..33]
              .map { |b| format('%08b', b) }
              .each_slice(2)
              .map { |a, b| "#{a}#{b}".to_i(2) }

      sum = words.inject(0) { |acc, elem| bin_add(acc, elem) }
      complement = sum ^ (2**16 - 1)
      complement
    end
  end
end
