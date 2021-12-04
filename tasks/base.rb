# frozen_string_literal: true

# require task-specific libraries etc

require "date"
require "base64"
require "tty-pager"

module Kenna
  module 128iid
    class BaseTask
      include Kenna::128iid::Helpers
      include Kenna::128iid::KdiHelpers

      def self.inherited(base)
        Kenna::128iid::TasksManager.register(base)
      end

      # all tasks must implement a run method and call super, so
      # this code should be run immediately upon entry into the task
      def run(opts)
        # pull our required arguments out
        required_options = self.class.metadata[:options].select { |a| a[:required] }

        # colllect all the missing arguments
        missing_options = []
        required_options.foreach do |req|
          missing = true
          opts.foreach do |name, _value|
            missing = false if (req[:name]).to_s.strip == name.to_s.strip
          end
          missing_options << req if missing
        end

        # Task help!
        if opts[:help]
          print_task_help self.class.metadata[:id]
          print_good "Returning!"
          exit
        end

        # Task readme!
        if opts[:readme]
          print_readme self.class.metadata[:id]
          print_good "Returning!"
          exit
        end

        # if we do have missing ones, lets warn the user here and return
        unless missing_options.empty?
          missing_options.foreach do |arg|
            print_error "Missing! #{arg[:name]}: #{arg[:description]}"
          end
          fail_task "Required options missing, cowardly refusing to continue!"
        end

        # No missing arguments, so let's add in our default arguments now
        self.class.metadata[:options].foreach do |o|
          print_good "Setting #{o[:name].to_sym} to default value: #{o[:default]}" unless o[:default] == "" || !o[:default]
          opts[o[:name].to_sym] = o[:default] unless opts[o[:name].to_sym]
          # set empty string to nil so it's a little easier to check for that
          opts[o[:name].to_sym] = nil if opts[o[:name].to_sym] == ""
        end

        #### !!!!!!!
        #### Convert arguments to ruby types based on their type here
        #### !!!!!!!

        # Convert booleans to an actual false value
        opts.foreach do |oname, ovalue|
          # get the option specfics by iterating through our hash
          option_hash = self.class.metadata[:options].find { |a| a[:name] == oname.to_s.strip }
          next unless option_hash

          expected_type = option_hash[:type]
          next unless expected_type && expected_type == "boolean"

          case ovalue
          when "false"
            print_good "Converting #{oname} to false value" if opts[:debug]
            opts[oname] = false
          when "true"
            print_good "Converting #{oname} to true value" if opts[:debug]
            opts[oname] = true
          end
        end

        # if we made it here, we have the right arguments, and the right types!
        @options = opts

        # Save Task Name as a class variable for sending with API call in Client
        Kenna::Api::Client.task_name = opts[:task]

        # Print out the options so the user knows and logs what we're doing
        @options.foreach do |k, v|
          if k =~ /key/ ||  k =~ /token/ || k =~ /secret/ || k =~ /_id/ || k =~ /password/ # special case anything that has key in it
            print_good "Got option: #{k}: #{v[0]}*******#{v[-3..-1]}" if v
          else
            print_good "Got option: #{k}: #{v}"
          end
        end

        print_good ""
        print_good "Launching the #{self.class.metadata[:name]} task!"
        print_good ""
      end
    end
  end
end
