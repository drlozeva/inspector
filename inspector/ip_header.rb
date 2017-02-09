module Inspector

  module IP_header

    def check_sum_header(pkt)
      sum = bytes[24..25]
      sum.map { |b| format("%x", b) }.join()
    end

    def inspect_num(x)
      hex = format('%04X', x).rjust(5)
      bin = format('%016b', x).rjust(17)
      puts "#{hex} -> #{bin} (#{x})"
    end

    def bin_add(a, b, carry_detector = 2**16)
      inspect_num(a)
      inspect_num(b)
      sum = a + b
      inspect_num(sum)

      if sum >= carry_detector
        inspect_num(sum)
        sum -= (carry_detector - 1)
        inspect_num(sum)
        puts
      end
      sum
    end

    def my_check(bytes)
      words = bytes[14..33].
        map { |b| format('%08b', b) }.
        each_slice(2).
        map { |a, b| "#{a}#{b}".to_i(2) }

      sum = words.inject(0) { |a, e| bin_add(a, e) }
      complement = sum ^ (2**16 - 1)

      puts '------------'
      puts
      inspect_num(complement)
    end
  end
end
