# frozen_string_literal: true

class Hash
  # Returns a copy of the receiver with recursively removed nil keys, empty strings, and empty arrays
  def deep_compact
    deep_dup.deep_compact!
  end

  # Mutate the receiver recursively removing nil keys, empty strings, and empty arrays
  def deep_compact!
    keys.each do |key|
      value = self[key]
      if value.nil? || (value.is_a?(String) && value.empty?) || (value.is_a?(Array) && value.empty?)
        delete key
      elsif value.is_a?(Hash)
        value.deep_compact!
      end
    end
    self
  end
end
