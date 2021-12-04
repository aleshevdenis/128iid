# frozen_string_literal: true

module Kenna
  module 128iid
    class Example < Kenna::128iid::BaseTask
      def self.metadata
        {
          id: "example",
          name: "Example Task",
          description: "This task is simply an example!",
          disabled: true,
          options: [
            {
              name: "example_option",
              type: "string",
              required: false,
              default: "just an example",
              description: "This is an example option. Set it to whatever you want and we'll print it"
            }
          ]
        }
      end

      def run(options)
        super

        # do things here
        print_good "Morpheus believes he is the one."
        print_debug "Everybody falls the first time" if @options[:debug]
        print_error "I'm just the messenger..."
        print "I know kung fu."
      end
    end
  end
end
