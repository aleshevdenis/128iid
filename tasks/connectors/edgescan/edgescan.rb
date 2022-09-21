# frozen_string_literal: true

require_relative "lib/edgescan_api"
require_relative "lib/edgescan_definition"
require_relative "lib/edgescan_host"
require_relative "lib/edgescan_location_specifier"
require_relative "lib/edgescan_vulnerability"
require_relative "lib/kenna_api"

module Kenna
  module 128iid
    class EdgescanTask < Kenna::128iid::BaseTask
      def self.metadata
        {
          id: "edgescan",
          name: "Edgescan",
          description: "Pulls assets and vulnerabilitiies from Edgescan",
          options: [
            { name: "edgescan_token",
              type: "api_key",
              required: true,
              default: nil,
              description: "Edgescan Token" },
            { name: "edgescan_page_size",
              type: "string",
              required: false,
              default: 100,
              description: "Edgescan page size" },
            { name: "edgescan_api_host",
              type: "hostname",
              required: false,
              default: "live.edgescan.com",
              description: "Edgescan API Hostname" },
            { name: "kenna_api_key",
              type: "api_key",
              required: false,
              default: nil,
              description: "Kenna API Key" },
            { name: "kenna_api_host",
              type: "hostname",
              required: false,
              default: "api.us.denist.dev",
              description: "Kenna API Hostname" },
            { name: "kenna_connector_id",
              type: "integer",
              required: true,
              default: nil,
              description: "Kenna connector ID" },
            { name: "output_directory",
              type: "filename",
              required: false,
              default: "output/edgescan",
              description: "The task will write JSON files here (path is relative to #{$basedir})" },
            { name: "create_findings",
              type: "boolean",
              required: false,
              default: false,
              description: "The task will create findings, instead of vulnerabilities" },
            { name: "network_vulns",
              type: "boolean",
              required: false,
              default: true,
              description: "The task will include network layer vulnerabilities" },
            { name: "application_vulns",
              type: "boolean",
              required: false,
              default: true,
              description: "The task will include application layer vulnerabilities" },
            { name: "assets_from_hosts",
              type: "boolean",
              required: false,
              default: false,
              description: "Create assets from edgescan hosts, do not use location specifier data" }
          ]
        }
      end

      def run(opts)
        if opts[:option] == "help"
          print_task_help self.class.metadata[:id]
          print_good "Returning!"
          exit
        end
        super # opts -> @options

        edgescan_api = Kenna::128iid::Edgescan::EdgescanApi.new(@options)
        kenna_api = Kenna::128iid::Edgescan::KennaApi.new(@options)

        edgescan_api.fetch_in_batches do |vulnerabilities, definitions, specifiers_hosts|
          kenna_api.add_assets(specifiers_hosts, vulnerabilities)
          if @options[:network_vulns] || @options[:application_vulns]
            if @options[:create_findings]
              kenna_api.add_findings(vulnerabilities)
            else
              kenna_api.add_vulnerabilities(vulnerabilities)
            end
          end

          kenna_api.add_definitions(definitions)

          kenna_api.upload
        end

        kenna_api.kickoff
      rescue Kenna::128iid::Edgescan::EdgescanApi::ApiError
        fail_task "Unable to retrieve assets, please check credentials"
      end
    end
  end
end
