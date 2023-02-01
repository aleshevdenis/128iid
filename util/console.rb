#!/usr/bin/env ruby
# frozen_string_literal: true

require_relative "../lib/128iid"
require "pry"

# Custom aliases for convenience
alias print puts
alias print_bad puts
alias print_good puts
alias print_error puts

# Load additional files and libraries
require_relative "./helpers"
require "csv"

# Define global variables
$program_name = "128iid"

# Load custom commands for the Pry REPL
Pry.commands.alias_command "c", "continue"
Pry.commands.alias_command "s", "step"
Pry.commands.alias_command "n", "next"

# Add custom information to the Pry prompt
prompt_proc = proc do |_obj, _nest_level, _pry|
  # Display the program name and version
  "[#{$program_name} v#{$version}] 128iid>"
end

# Start the Pry REPL
Pry.start(self, prompt: [prompt_proc])