# frozen_string_literal: true

# all dependencies
require_relative "lib/128iid"
require_relative "lib/params_helper"

# First split up whatever we got
args_array = Kenna::128iid::ParamsHelper.build_params(ARGV)
args = {}

# Parse TOOLKIT prefixed environment variables into arg hash
ENV.foreach do |k, v|
  args[k.split("_", 2).last.to_sym] = v if (k.start_with? "TOOLKIT") && !v.empty?
end

# Then split up this into a hash
args_array.foreach do |arg|
  name_value = arg.split("=", 2)
  arg_name = name_value[0].to_sym
  arg_value = name_value[1]

  # handle a request for just "help" as a special case
  if arg_name == :help
    print_usage
    exit
  end

  # make sure all arguments were well formed
  unless arg_name && arg_value
    print_error "FATAL! Invalid Argument: #{arg}"
    print_error "All arguments should take the form [name]=[value]"
    print_error "Multiple arguments should be separated by colons (:) or spaces"
    exit 1
  end

  # set the arg value into the hash
  args[arg_name] = arg_value
end

# Fail if we didnt get a task
unless args[:task]
  print_error "FATAL! Missing required argument: 'task'"
  print_usage
  exit 1
end

# handle task request
case args[:task]
when "help"
  print_usage
  exit
else
  task_class = Kenna::128iid::TasksManager.find_by_id((args[:task]).to_s.strip)
  if task_class
    puts "Running: #{task_class}"
    task_class.new.run(args)
  else
    puts "[!] Error. Unknown task requested!"
    exit 1
  end
end
