# frozen_string_literal: true

module Kenna
  module 128iid
    module DebugHelper
      class << self
        attr_accessor :debug, :running_local

        def debug?
          @debug ||= false
        end

        def running_local?
          @running_local ||= true
        end
      end
    end
  end
end