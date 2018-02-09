module Jekyll
	module RegexFilter
		def replace_regex(input, regex_string, replace_string)
			regex = Regexp.new regex_string
			input.gsub regex, replace_string
		end
	end
end

Liquid::Template.register_filter(Jekyll::RegexFilter)
