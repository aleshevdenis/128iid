# frozen_string_literal: true

require_relative "lib/bitsight_helpers"

module Kenna
  module 128iid
    class BitsightTask < Kenna::128iid::BaseTask
      include Kenna::128iid::BitsightHelpers

      def self.metadata
        {
          id: "bitsight",
          name: "Bitsight",
          description: "This task connects to the Bitsight API and pulls results into the Kenna Platform.",
          options: [
            { name: "bitsight_api_key",
              type: "string",
              required: true,
              default: "",
              description: "This is the Bitsight key used to query the API." },
            { name: "bitsight_benign_finding_grades",
              type: "string",
              required: false,
              default: "GOOD,NEUTRAL",
              description: "Any bitsight findings with this grade will be considered benign (comma delimited list)" },
            { name: "bitsight_create_benign_findings",
              type: "boolean",
              required: false,
              default: true,
              description: "Create (informational) vulns for findings labeled benign" },
            { name: "bitsight_company_guids",
              type: "string",
              required: false,
              default: "",
              description: "Comma separated list of company guids to use for data pull. If nil, script will pull for 'My Company' only" },
            { name: "bitsight_lookback",
              type: "integer",
              required: false,
              default: 90,
              description: "Integer to pull the last n days of findings" },
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
              default: "output/bitsight",
              description: "If set, will write a file upon completion. Path is relative to #{$basedir}" }
          ]
        }
      end

      def run(options)
        super

        @kenna_api_host = @options[:kenna_api_host]

        @kenna_api_key = @options[:kenna_api_key]
        @kenna_connector_id = @options[:kenna_connector_id]
        bitsight_api_key = @options[:bitsight_api_key]
        @output_dir = "#{$basedir}/#{@options[:output_directory]}"
        company_guids = @options[:bitsight_company_guids].split(",") unless @options[:bitsight_company_guids].nil?
        bitsight_create_benign_findings = @options[:bitsight_create_benign_findings]
        benign_finding_grades = (@options[:bitsight_benign_finding_grades]).to_s.split(",")

        globals(bitsight_api_key)
        ### Basic Sanity checking
        if valid_bitsight_api_key?
          print_good "Valid key, proceeding!"
        else
          fail_task "Unable to proceed, invalid key for Bitsight?"
        end
        fm = Kenna::128iid::Data::Mapping::DigiFootprintFindingMapper.new(@output_dir, @options[:input_directory], @options[:df_mapping_filename])
        bitsight_findings_and_create_kdi(bitsight_create_benign_findings, benign_finding_grades, company_guids, fm, @options[:bitsight_lookback])

        ### Write KDI format
        print_good "Attempting to run to Kenna Connector at #{@kenna_api_host}"
        kdi_connector_kickoff(@kenna_connector_id, @kenna_api_host, @kenna_api_key)
      end
    end
  end
end
