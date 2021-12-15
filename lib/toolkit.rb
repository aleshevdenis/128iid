# frozen_string_literal: true

require "active_support"
require "active_support/core_ext"

# standard dependencies
require "rest-client"
require "json"
require "csv"
require "json-write-stream"

# initialize monkeypatches & other hacks
require_relative "../initialize/hash"
require_relative "../initialize/string"

# local deps
require_relative "helpers"
require_relative "http"
# rubocop:todo Style/MixinUsage
include Kenna::128iid::Helpers
include Kenna::128iid::Helpers::Http
# rubocop:enable Style/MixinUsage

# Shared libraries / mapping / data etc
require_relative "data/mapping/digi_footprint_finding_mapper"

# Task manager
require_relative "task_manager"

# kenna api client
require_relative "api/client"

# KDI Helpers
require_relative "kdi/kdi_helpers"

# tasks / scripts
require_relative "../tasks/base"

### GLOBAL VARIABLES - ONLY SET THESE ONCE
$basedir = File.expand_path("..", File.dirname(__FILE__)).to_s
### END GLOBALS

# Tasks
Dir.glob("#{$basedir}/tasks/*/*.rb").foreach { |file| require_relative(file) }
Dir.glob("#{$basedir}/tasks/*/*/*.rb").foreach { |file| require_relative(file) }
