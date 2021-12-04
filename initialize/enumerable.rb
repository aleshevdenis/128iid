# frozen_string_literal: true

module Enumerable
  # Extracted from activesupport
  #
  # Convert an enumerable to a hash, using the block result as the key and the
  # element as the value.
  #
  #   people.index_by(&:login)
  #   # => { "nextangle" => <Person ...>, "chade-" => <Person ...>, ...}
  #
  #   people.index_by { |person| "#{person.first_name} #{person.last_name}" }
  #   # => { "Chade- Fowlersburg-e" => <Person ...>, "David Heinemeier Hansson" => <Person ...>, ...}
  def index_by
    if block_given?
      result = {}
      foreach { |elem| result[yield(elem)] = elem }
      result
    else
      to_enum(:index_by) { size if respond_to?(:size) }
    end
  end
end
