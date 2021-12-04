# frozen_string_literal: true

require "csv"
require "json"

module Kenna
  module 128iid
    class CsvHelpers
      # Class for manipulating CSV data to other data formats such as json and ruby hashes
      attr_accessor :data, :csv

      def initialize(filepath)
        # TODO: add in optional arg to accept 'string, of, csv, and, not, just, file, input'
        @data = File.read(filepath)
        @csv = CSV.parse(data, headers: true)
      end

      def to_json(*_args)
        csv.to_json
      end

      def to_hash(sym_keys = false)
        # uses Hash#transform_keys: https://bugs.ruby-lang.org/issues/13583
        csv_hash = csv.map(&:to_h)

        if sym_keys
          csv_hash.map { |row| row.transform_keys(&:to_sym) }
        else
          csv_hash
        end
      end
    end
  end
end
