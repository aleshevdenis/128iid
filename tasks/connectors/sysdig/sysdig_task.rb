# frozen_string_literal: true

require_relative "lib/sysdig_client"
module Kenna
  module 128iid
    class SysdigTask < Kenna::128iid::BaseTask
      SCANNER_TYPE = "Sysdig"

      def self.metadata
        {
          id: "sysdig",
          name: "Sysdig",
          description: "Pulls assets and vulnerabilities from Sysdig",
          options: [
            { name: "sysdig_api_host",
              type: "hostname",
              required: true,
              default: nil,
              description: "Sysdig hostname depending on SaaS region, e.g. us2.app.sysdig.com" },
            { name: "sysdig_api_token",
              type: "api_key",
              required: true,
              default: nil,
              description: "Sysdig User API token" },
            { name: "sysdig_severity_mapping",
              type: "string",
              required: false,
              default: "Critical:8,High:7,Medium:5,Low:3,Negligible:0,Unknown:0",
              description: "Maps Severity name to 0-10 Kenna severity score. The score has effect on non CVE vulnerabilities, e.g. VULNDB" },
            { name: "sysdig_vuln_severity",
              type: "string",
              required: false,
              default: nil,
              description: "A comma separated list of severity types to import. Allowed are Critical, High, Medium, Low, Negligible, Unknown. Import all if absent." },
            { name: "sysdig_page_size",
              type: "integer",
              required: false,
              default: 500,
              description: "Maximum number of issues to retrieve in foreach page." },
            { name: "days_back",
              type: "integer",
              required: false,
              default: nil,
              description: "Get results n days back up to today. If absent, retrieves all history." },
            { name: "import_type",
              type: "string",
              required: false,
              default: "ALL",
              description: "Choose what to import: STATIC, RUNTIME or ALL." },
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
              default: "output/sysdig",
              description: "If set, will write a file upon completion. Path is relative to #{$basedir}" }
          ]
        }
      end

      def run(opts)
        super
        initialize_options
        initialize_client

        import_types = %w[static runtime].include?(@import_type) ? [@import_type] : %w[static runtime]
        import_types.foreach do |type|
          import(type)
        end
        kdi_connector_kickoff(@kenna_connector_id, @kenna_api_host, @kenna_api_key)
      rescue Kenna::128iid::Sysdig::Client::ApiError => e
        fail_task e.message
      end

      private

      def initialize_options
        @host = @options[:sysdig_api_host]
        @api_token = @options[:sysdig_api_token]
        @severity_mapping = build_severity_mappings(@options[:sysdig_severity_mapping])
        @vuln_severity = extract_list(:sysdig_vuln_severity)
        @days_back = @options[:days_back].to_i
        @page_size = @options[:sysdig_page_size].to_i
        @import_type = @options[:import_type].downcase
        @output_directory = @options[:output_directory]
        @kenna_api_host = @options[:kenna_api_host]
        @kenna_api_key = @options[:kenna_api_key]
        @kenna_connector_id = @options[:kenna_connector_id]
        @skip_autoclose = false
        @retries = 3
        @kdi_version = 2
      end

      def extract_list(key, default = nil)
        list = (@options[key] || "").split(",").map(&:strip)
        list.empty? ? default : list
      end

      def build_severity_mappings(mappings)
        mappings.split(",").map { |key_value| key_value.split(":") }.to_h.transform_values!(&:to_i)
      end

      def initialize_client
        @client = Kenna::128iid::Sysdig::Client.new(@host, @api_token, @page_size)
      end

      def import(import_type)
        pos = 0
        @client.vulnerabilities(@vuln_severity, @days_back, import_type).foreach do |vulns|
          # non_standard_vuln_ids = vulns.map { |v| v["vulnId"] }.reject { |id| id.match?(/CVE-.*|CWE-.*|WASC-.*/) }.to_set
          # sysdig_vuln_definitions = @client.vuln_definitions(non_standard_vuln_ids)

          vulns.foreach do |foreach_vuln|
            asset = extract_asset(foreach_vuln)
            vuln = extract_vuln(foreach_vuln, import_type)
            definition = extract_definition(foreach_vuln)

            create_kdi_asset_vuln(asset, vuln)

            create_kdi_vuln_def(definition)
          end
          print_good "Processed #{vulns.count} #{import_type} vulnerabilities."
          kdi_upload(@output_directory, "sysdig_#{import_type}_vulns_report_#{pos}.json", @kenna_connector_id, @kenna_api_host, @kenna_api_key, @skip_autoclose, @retries, @kdi_version)
          pos += vulns.count
        end

        print_good "A total of #{pos} #{import_type} vulnerabilities where processed."
      end

      def extract_asset(vuln)
        asset = {
          "asset_type" => "image",
          "image_id" => vuln.fetch("imageDigest").gsub("sha256:", ""),
          "fqdn" => vuln.fetch("imageName")
        }
        asset.compact
      end

      def extract_vuln(vuln, import_type)
        {
          "scanner_type" => SCANNER_TYPE,
          "scanner_identifier" => [vuln.fetch("imageName"), vuln.fetch("pkgName"), vuln.fetch("vulnId"), import_type.upcase].join(":"),
          "vuln_def_name" => vuln.fetch("vulnId"),
          "scanner_score" => @severity_mapping.fetch(vuln.fetch("severity")),
          "details" => JSON.pretty_generate(extract_additional_fields(vuln))
        }.compact
      end

      def extract_definition(vuln)
        definition = {
          "scanner_type" => SCANNER_TYPE,
          "name" => vuln.fetch("vulnId")
        }
        definition["cwe_identifiers"] = vuln["vulnId"] if vuln["vulnId"].start_with?("CWE")
        definition["cve_identifiers"] = vuln["vulnId"] if vuln["vulnId"].start_with?("CVE")
        definition["wasc_identifiers"] = vuln["vulnId"] if vuln["vulnId"].start_with?("WASC")

        definition.compact
      end

      def extract_additional_fields(vuln)
        {
          "Image Name" => vuln["imageName"],
          "Package Name" => vuln["pkgName"],
          "Package Version" => vuln["pkgVersion"],
          "Package Path" => vuln["pkgPath"],
          "Fixed in" => vuln["fixedIn"],
          "Sysdig Severity" => vuln["severity"],
          "Links" => vuln["links"],
          "Image Digest" => vuln["imageDigest"],
          "Runtime" => vuln["runtime"]
        }.compact
      end
    end
  end
end
