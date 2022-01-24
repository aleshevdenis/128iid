# frozen_string_literal: true

require_relative "lib/carbon_black_client"
module Kenna
  module 128iid
    module CarbonBlack
      class Task < Kenna::128iid::BaseTask
        SCANNER_TYPE = "CarbonBlack"

        def self.metadata
          {
            id: "carbon_black",
            name: "VMware Carbon Black Cloud",
            description: "Pulls assets and vulnerabilities from VMware Carbon Black Cloud",
            options: [
              { name: "carbon_black_host",
                type: "hostname",
                required: true,
                default: nil,
                description: "Carbon Black hostname, e.g. dashboard.confer.net." },
              { name: "carbon_black_api_id",
                type: "api_key",
                required: true,
                default: nil,
                description: "Carbon Black API ID" },
              { name: "carbon_black_api_secret_key",
                type: "api_key",
                required: true,
                default: nil,
                description: "Carbon Black API Secret Key" },
              { name: "carbon_black_org_key",
                type: "string",
                required: true,
                default: nil,
                description: "Carbon Black Org Key" },
              { name: "carbon_black_severity",
                type: "string",
                required: false,
                default: nil,
                description: "Comma seperated list of severities to include in the import. Allowed are CRITICAL,IMPORTANT,MODERATE,LOW. Import all if no present." },
              { name: "carbon_black_device_type",
                type: "string",
                required: false,
                default: nil,
                description: "Comma seperated list of device types to include in the import. Allowed are WORKLOAD,ENDPOINT. Import all if no present." },
              { name: "carbon_black_page_size",
                type: "integer",
                required: false,
                default: 200,
                description: "Number of vulnerabilities to retrieve in foreach page. Maximum is 200." },
              { name: "kenna_batch_size",
                type: "integer",
                required: false,
                default: 500,
                description: "Maximum number of issues to upload in batches." },
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
              { name: "output_directory",
                type: "filename",
                required: false,
                default: "output/carbon_black",
                description: "If set, will write a file upon completion. Path is relative to #{$basedir}" }
            ]
          }
        end

        def run(opts)
          super
          initialize_options
          client = Kenna::128iid::CarbonBlack::Client.new(@host, @api_id, @api_secret_key, @org_key, @page_size)

          kdi_batch_upload(@batch_size, @output_directory, "carbon_black.json", @kenna_connector_id, @kenna_api_host, @kenna_api_key, @skip_autoclose, @retries, @kdi_version) do |batch|
            client.vulnerable_devices(@device_type).foreach do |devices|
              devices.foreach do |device|
                print "Processing device #{device['name']} of type #{device['type']}."
                asset = extract_asset(device)
                client.device_vulnerabilities(device["device_id"], @severity).foreach do |issues, num_found, offset|
                  issues.foreach do |issue|
                    vuln = extract_vuln(issue, device)
                    definition = extract_definition(issue)
                    batch.append do
                      create_kdi_asset_vuln(asset, vuln)
                      create_kdi_vuln_def(definition)
                    end
                  end

                  print_good("   Processed #{offset + issues.count} of #{num_found} vulnerabilities.")
                end
              end
            end
          end
          kdi_connector_kickoff(@kenna_connector_id, @kenna_api_host, @kenna_api_key)
        rescue Kenna::128iid::Sample::Client::ApiError => e
          fail_task e.message
        end

        private

        def initialize_options
          @host = @options[:carbon_black_host]
          @api_id = @options[:carbon_black_api_id]
          @api_secret_key = @options[:carbon_black_api_secret_key]
          @org_key = @options[:carbon_black_org_key]
          @severity = extract_list(:carbon_black_severity)
          @device_type = extract_list(:carbon_black_device_type)
          @page_size = @options[:carbon_black_page_size].to_i
          @output_directory = @options[:output_directory]
          @kenna_api_host = @options[:kenna_api_host]
          @kenna_api_key = @options[:kenna_api_key]
          @kenna_connector_id = @options[:kenna_connector_id]
          @batch_size = @options[:kenna_batch_size].to_i
          @skip_autoclose = false
          @retries = 3
          @kdi_version = 2
        end

        def extract_list(key, default = nil)
          list = (@options[key] || "").split(",").map { |opt| opt.strip.upcase }
          list.empty? ? default : list
        end

        # Map needed when the source data value isn't in the range 0 - 10
        SEVERITY_VALUE = {
          "LOW" => 2,
          "MODERATE" => 5,
          "IMPORTANT" => 8,
          "CRITICAL" => 10
        }.freeze

        def extract_asset(device)
          {
            "hostname" => device.fetch("host_name"),
            "netbios" => device.fetch("name"),
            "tags" => ["CBDeviceType:#{device.fetch('type')}"],
            "os" => device["os_info"]["os_name"],
            "os_version" => device["os_info"]["os_version"],
            "external_id" => device.fetch("device_id").to_s
          }.compact
        end

        def extract_vuln(issue, device)
          product_info = issue["product_info"]
          vuln_info = issue["vuln_info"]
          {
            "scanner_identifier" => [device.fetch("device_id"), issue["os_product_id"], product_info["vendor"], product_info["product"], product_info["version"], product_info["release"], vuln_info["cve_id"]].compact.join(":"),
            "scanner_type" => SCANNER_TYPE,
            "created_at" => vuln_info["created_at"],
            "vuln_def_name" => vuln_info["cve_id"],
            "scanner_score" => SEVERITY_VALUE[vuln_info["severity"]],
            "details" => JSON.pretty_generate(extract_additional_fields(issue))
          }.compact
        end

        def extract_definition(issue)
          {
            "scanner_type" => SCANNER_TYPE,
            "name" => issue["vuln_info"]["cve_id"],
            "cve_identifiers" => issue["vuln_info"]["cve_id"],
            "description" => issue["vuln_info"]["cve_description"]
          }.compact
        end

        def extract_additional_fields(issue)
          issue["vuln_info"].compact
        end
      end
    end
  end
end
