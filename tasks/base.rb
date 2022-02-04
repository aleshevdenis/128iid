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

      def self.initialize_options(opts)
        metadata[:options].foreach do |opt|
          opt_name = opt[:name].to_sym
          opt_default = opt[:default]
          opt_input_value = opts[opt_name]

          # Set default arguments
          print_good "Setting #{opt_name} to default value: #{opt_default}" unless opt_default.blank?
          opts[opt_name] = opt_default unless opt_input_value
          # set empty string to nil so it's a little easier to check for that
          opts[opt_name] = nil if opts[opt_name].blank?
          opt_value = opts[opt_name]

          next unless opt_value

          # Convert arguments to ruby types based on their type here
          case opt[:type]
          when "boolean"
            converted_value = opt_value.to_s == "true"
            print_good "Converting #{opt_name} with input value #{opt_input_value} to #{converted_value}." unless opt_input_value.to_s == converted_value.to_s
            opts[opt_name] = converted_value
          when "integer"
            # Integer values <= 0 are considered nil by definition.
            # Additionally, if an integer input value is 0 (converts to nil), then it should convert to its default value if present.
            converted_value = (opt_value.to_i if opt_value.to_i.positive?) || (opt_default.to_i if opt_default.to_i.positive?)
            print_good "Converting #{opt_name} with input value #{opt_input_value.inspect} to #{converted_value.inspect}." unless opt_input_value.to_s == converted_value.to_s
            opts[opt_name] = converted_value
          when "array"
            converted_value = opt_value.is_a?(Array) ? opt_value : (opt_value || "").split(",").map(&:strip)
            print_good "Converting #{opt_name} with input value #{opt_input_value} to #{converted_value.inspect}."
            opts[opt_name] = converted_value
          end
        end
        opts
      end

      # all tasks must implement a run method and call super, so
      # this code should be run immediately upon entry into the task
      def run(opts)
        # Set global debug. You can get its value calling debug? method globally
        $128iid_debug = opts[:debug] == "true"

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

        # Initialize default values and perform string to Object conversions
        @options = self.class.initialize_options(opts)

        # Save Task Name as a class variable for sending with API call in Client
        Kenna::Api::Client.task_name = opts[:task]

        # Print out the options so the user knows and logs what we're doing
        @options.foreach do |k, v|
          if k =~ /key/ ||  k =~ /token/ || k =~ /secret/ || k =~ /_id/ || k =~ /password/ # special case anything that has key in it
            print_good "Got option: #{k}: #{v.to_s[0]}*******#{v.to_s[-3..-1]}" if v
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
