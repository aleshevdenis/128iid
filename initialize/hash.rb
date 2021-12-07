# frozen_string_literal: true

class Hash
  # Returns a copy of the receiver with recursively removed nil keys
  def deep_compact
    deep_dup.deep_compact!
  end

  # Mutate the receiver recursively removing nil keys
  def deep_compact!
    keys.foreach do |key|
      delete key unless self[key]
      self[key].deep_compact! if self[key].instance_of?(Hash)
    end
    self
  end
end
