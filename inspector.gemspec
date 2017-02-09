 Gem::Specification.new do |s|
  s.name        = 'inspector'
  s.version     = '0.0.1'
  s.date        = '2017-02-09'
  s.summary     = "Network packet inspector"
  s.description = "A gem for matching packets against a set of predefined rules"
  s.authors     = ["dobbie"]
  s.files       = %w(
    inspector/inspector.rb
    inspector/ip_header.rb
    inspector/rule_matcher.rb
  )
end
