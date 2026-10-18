#!/usr/bin/env ruby
# Approximate Flesch-Kincaid grade-level checker for a Markdown file.
# Usage: ruby scripts/flesch_kincaid.rb README.md

path = ARGV[0] || 'README.md'
text = File.read(path, encoding: 'UTF-8')
text = text.gsub(/```.*?```/m, ' ').gsub(/`[^`]*`/, ' ')
text = text.gsub(/!\[[^\]]*\]\([^)]*\)/, ' ').gsub(/\[[^\]]*\]\([^)]*\)/, ' ')
words = text.scan(/[A-Za-z]+(?:'[A-Za-z]+)?/)
sentences = text.scan(/[.!?]+(?=\s|$)/).length
sentences = 1 if sentences.zero?
syllables = words.sum do |word|
  w = word.downcase
  count = w.scan(/[aeiouy]+/).length
  count -= 1 if w.match?(/e\z/) && !w.match?(/le\z/) && count > 1
  count = 1 if count < 1
  count
end
word_count = [words.length, 1].max
syllables_per_word = syllables.to_f / word_count
words_per_sentence = word_count.to_f / sentences
grade = 0.39 * words_per_sentence + 11.8 * syllables_per_word - 15.59
puts "File: #{path}"
puts "Words: #{word_count}"
puts "Sentences: #{sentences}"
puts format('Approx. Flesch-Kincaid grade: %.2f', grade)
