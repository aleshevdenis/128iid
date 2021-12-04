# frozen_string_literal: true

module Kenna
  module 128iid
    module ParamsHelper
      # Helper used to build params from command line
      # This implementation accepts whitespaces and colons as separators.
      # Colons are ignored as separators when inside double quoted strings.
      # @return [Array<String>]
      def self.build_params(params_array)
        params_array.map { |arg| parse_param(arg) }.flatten
      end

      def self.parse_param(string)
        input = string.chars
        params = []
        param = +""
        escaping = false

        until input.empty?
          char = input.shift
          case char
          when '"'
            escaping = !escaping
          when ":"
            if escaping
              param << char
            else
              params << param
              param = +""
            end
          else
            param << char
          end
        end
        params << param unless param.empty?
        params
      end
    end
  end
end
