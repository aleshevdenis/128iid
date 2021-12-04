# frozen_string_literal: true

# extend client
require_relative "lib/extend_issues_client"

# cloud exposure field mappings
require_relative "lib/extend_issues_mapper"

module Kenna
  module 128iid
    class ExpanseIssuesTask < Kenna::128iid::BaseTask
      include Kenna::128iid::ExpanseIssues::ExpanseIssuesMapper

      def self.metadata
        {
          id: "extend_issues",
          name: "ExpanseIssues",
          description: "This task connects to the Expanse API and pulls results into the Kenna Platform.",
          options: [
            { name: "extend_api_key",
              type: "string",
              required: true,
              default: "",
              description: "This is the Expanse key used to query the API." },
            { name: "issue_types",
              type: "string",
              required: false,
              default: "",
              description: "Comma-separated list of issue types. If not set, all issue types will be included" },
            { name: "priorities",
              type: "string",
              required: false,
              default: "",
              description: "Comma-separated list of priorities. If not set, all priorities will be included" },
            { name: "tagNames",
              type: "string",
              required: false,
              default: "",
              description: "Comma-separated list of tag names. If not set, all tags will be included" },
            { name: "lookback",
              type: "integer",
              required: false,
              default: 90,
              description: "Integer to retrieve the last n days of issues" },
            { name: "extend_page_size",
              type: "integer",
              required: false,
              default: 10_000,
              description: "Comma-separated list of tag names. If not set, all tags will be included" },
            { name: "kenna_api_key",
              type: "api_key",
              required: false,
              default: nil,
              description: "Kenna API Key" },
            { name: "kenna_api_host",
              type: "hostname",
              required: false,
              default: "api.denist.dev",
              description: "Kenna API Hostname" },
            { name: "kenna_connector_id",
              type: "integer",
              required: false,
              default: nil,
              description: "If set, we'll try to upload to this connector" },
            { name: "df_mapping_filename",
              type: "string",
              required: false,
              default: nil,
              description: "If set, we'll use this external file for vuln mapping - use with input_directory" },
            { name: "output_directory",
              type: "filename",
              required: false,
              default: "output/extend",
              description: "If set, will write a file upon completion. Path is relative to #{$basedir}" }
          ]
        }
      end

      def run(options)
        super

        # Get options
        @kenna_api_host = @options[:kenna_api_host]
        @kenna_api_key = @options[:kenna_api_key]
        @kenna_connector_id = @options[:kenna_connector_id]
        @uploaded_files = []
        @output_dir = "#{$basedir}/#{@options[:output_directory]}"
        @issue_types = @options[:issue_types].split(",") if @options[:issue_types]
        @priorities =  @options[:priorities] if @options[:priorities]
        @tags = @options[:tagNames] if @options[:tagNames]
        extend_api_key = @options[:extend_api_key]

        print @issue_types
        print @priorities

        # create an api client
        @client = Kenna::128iid::ExpanseIssues::ExpanseIssuesClient.new(extend_api_key)
        @fm = Kenna::128iid::Data::Mapping::DigiFootprintFindingMapper.new(@output_dir, @options[:input_directory], @options[:df_mapping_filename])

        @assets = []
        @vuln_defs = []

        # verify we have a good key before proceeding
        fail_task "Unable to proceed, invalid key for Expanse?" unless @client.successfully_authenticated?
        print_good "Valid key, proceeding!"

        create_kdi_from_issues(@options[:extend_page_size], @issue_types, @priorities, @tags, @fm, @options[:lookback])

        ####
        ### Finish by uploading if we're all configured
        ####
        return unless @kenna_connector_id && @kenna_api_host && @kenna_api_key

        kdi_kickoff
      end
    end
  end
end
