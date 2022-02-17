# frozen_string_literal: true

require_relative "lib/riskiq_helper"

module Kenna
  module 128iid
    class RiskIqTask < Kenna::128iid::BaseTask
      include Kenna::128iid::RiskIQHelper

      def self.metadata
        {
          id: "riskiq",
          name: "RiskIQ",
          description: "This task connects to the RiskIQ API and pulls results into the Kenna Platform.",
          options: [
            { name: "riskiq_api_key",
              type: "api_key",
              required: true,
              default: "",
              description: "This is the RiskIQ key used to query the API." },
            { name: "riskiq_api_secret",
              type: "api_key",
              required: true,
              default: "",
              description: "This is the RiskIQ secret used to query the API." },
            { name: "riskiq_create_cves",
              type: "boolean",
              required: true,
              default: true,
              description: "Create vulns for CVEs" },
            { name: "riskiq_pull_incremental",
              type: "boolean",
              required: false,
              default: false,
              description: "LastRun timestamp will be created in input directory and used as the basis for subsequent runs" },
            { name: "riskiq_incremental_time",
              type: "string",
              required: false,
              default: "2 days ago",
              description: "Timefame to be used with pull_incremental flag. Example: '14 days ago'" },
            { name: "riskiq_create_ssl_misconfigs",
              type: "boolean",
              required: true,
              default: false,
              description: "Create vulns for SSL Miconfigurations" },
            { name: "riskiq_create_open_ports",
              type: "boolean",
              required: true,
              default: false,
              description: "Create vulns for open ports" },
            { name: "riskiq_port_last_seen",
              type: "integer",
              required: false,
              default: 14,
              description: "Limit ports by number of days when last seen." },
            { name: "riskiq_inventory_states",
              type: "string",
              required: false,
              default: "Candidate,CONFIRMED",
              description: "List of Inventory States." },
            { name: "riskiq_page_size",
              type: "integer",
              required: false,
              default: 50,
              description: "Page size for calls to riskiq. Must be less than 1000. High page size without pull_incremental may lead to OOM failure" },
            { name: "batch_page_size",
              type: "integer",
              required: false,
              default: 300,
              description: "Number of assets and their vulns to batch to the connector" },
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
              default: "output/riskiq",
              description: "If set, will write a file upon completion. Path is relative to #{$basedir}" }
          ]
        }
      end

      def run(options)
        super

        kenna_api_host = @options[:kenna_api_host]
        kenna_api_key = @options[:kenna_api_key]
        kenna_connector_id = @options[:kenna_connector_id]
        @batch_page_size = @options[:batch_page_size].to_i

        riq_api_key = @options[:riskiq_api_key]
        riq_api_secret = @options[:riskiq_api_secret]
        riq_pull_incremental = @options[:riskiq_pull_incremental]
        riq_incremental_time = @options[:riskiq_incremental_time]

        @riq_create_cves = @options[:riskiq_create_cves]
        @riq_create_ssl_misconfigs = @options[:riskiq_create_ssl_misconfigs]
        @riq_create_open_ports = @options[:riskiq_create_open_ports]
        output_directory = @options[:output_directory]
        @riq_inventory_states = @options[:riskiq_inventory_states].split(",")

        # create an api client
        set_client_data(riq_api_key, riq_api_secret, kenna_connector_id, kenna_api_host, kenna_api_key, output_directory, riq_incremental_time, riq_pull_incremental, @options[:riskiq_port_last_seen])

        if @riq_create_cves
          print_good "Getting CVEs from footprint"
          search_global_inventory(cve_footprint_query, @batch_page_size, @options[:riskiq_page_size])
        end

        if @riq_create_open_ports
          print_good "Getting open ports from footprint"
          search_global_inventory(open_port_query, @batch_page_size, @options[:riskiq_page_size])
        end

        if @riq_create_ssl_misconfigs
          print_good "Getting ssl information from footprint"
          search_global_inventory(ssl_cert_query, @batch_page_size, @options[:riskiq_page_size])
          print_good "Getting expired ssl information from footprint"
          search_global_inventory(expired_ssl_cert_query("[\"Expired\",\"Expires30\"]"), @batch_page_size, @options[:riskiq_page_size])
        end

        return unless @kenna_connector_id && @kenna_api_host && @kenna_api_key

        kdi_connector_kickoff(@kenna_connector_id, @kenna_api_host, @kenna_api_key)
      rescue Kenna::128iid::RiskIQHelper::ApiError
        fail_task "Unable to retrieve data from API, please check credentials or increase riskiq_port_last_seen"
      end
    end
  end
end
