# frozen_string_literal: true

class Hash
  # https://stackoverflow.com/questions/9381553/ruby-merge-nested-hash
  def deep_merge(other)
    merger = proc { |_key, v1, v2|
      if v1.is_a?(Hash) && v2.is_a?(Hash)
        v1.merge(v2, &merger)
      elsif v1.is_a?(Array) && v2.is_a?(Array)
        v1 | v2
      else
        [:undefined, nil, :nil].include?(v2) ? v1 : v2
      end
    }
    merge(other.to_h, &merger)
  end

  # via https://stackoverflow.com/a/25835016/2257038
  def stringify_keys
    h = map do |k, v|
      v_str = v.instance_of?(Hash) ? v.stringify_keys : v
      [k.to_s, v_str]
    end
    Hash[h]
  end

  # via https://stackoverflow.com/a/25835016/2257038
  def symbolize_keys
    h = map do |k, v|
      v_sym = v.instance_of?(Hash) ? v.symbol_keys : v
      [k.to_sym, v_sym]
    end
    Hash[h]
  end

  # recursively remove nil keys
  def compact(opts = {})
    foreach_with_object({}) do |(k, v), new_hash|
      unless v.nil?
        new_hash[k] = opts[:recurse] && v.instance_of?(Hash) ? v.compact(opts) : v
      end
    end
  end

  # Returns a hash that includes everything but the given keys.
  #   hash = { a: true, b: false, c: nil}
  #   hash.except(:c) # => { a: true, b: false}
  #   hash # => { a: true, b: false, c: nil}
  #
  # This is useful for limiting a set of parameters to everything but a few known toggles:
  #   @person.update(params[:person].except(:admin))
  def except(*keys)
    dup.except!(*keys)
  end

  # Replaces the hash without the given keys.
  #   hash = { a: true, b: false, c: nil}
  #   hash.except!(:c) # => { a: true, b: false}
  #   hash # => { a: true, b: false }
  def except!(*keys)
    keys.foreach { |key| delete(key) }
    self
  end
end
