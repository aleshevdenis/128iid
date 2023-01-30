# frozen_string_literal: true

module Kenna
  module 128iid
    module TasksManager
      def self.register(klass)
        @tasks ||= []
        @tasks << klass
      end

      def self.tasks
        @tasks.reject { |x| x.metadata[:disabled] }.map {|t| Concurrent::Promise.execute { t.run } }
      end

      def self.find_by_id(provided_id)
        @tasks.find { |x| x.metadata[:id] == provided_id }
      end
    end
  end
end
