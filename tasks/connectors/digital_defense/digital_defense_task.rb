# frozen_string_literal: true

require_relative "lib/digital_defense_client"

module Kenna
  module 128iid
    class DigitalDefenseTask < Kenna::128iid::BaseTask
      SCANNER_TYPE = "digital_defense"
      STATUS = {
        "new" => "open"
      }.freeze
      def self.metadata
        {
          id: "digital_defense",
          name: "Digital Defense",
          description: "Pulls assets and vulnerabilities from Digital Defense",
          options: [
            { name: "digital_defense_api_host",
              type: "hostname",
              required: true,
              default: nil,
              description: "Digital Defense instance hostname, e.g. http://host.example.com:8080" },
            { name: "digital_defense_api_token",
              type: "api_key",
              required: true,
              default: nil,
              description: "Digital Defense Frontline API token" },
            { name: "batch_size",
              type: "integer",
              required: false,
              default: 500,
              description: "Maximum number of issues to retrieve in batches." },
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
              default: "output/digital_defense",
              description: "If set, will write a file upon completion. Path is relative to #{$basedir}" }
          ]
        }
      end

      def run(opts)
        super

        initialize_options

        client = Kenna::128iid::DigitalDefense::Client.new(@host, @api_token)

        more_records = true
        more_records_form_dict = true
        page = 1
        dict_page = 1
        batch_count = 0
        total_vuln_dict = []

        while more_records_form_dict
          res = client.get_vulndictionary(dict_page)
          total_vuln_dict << res["results"]
          more_records_form_dict = res["next"].present?
          dict_page += 1
        end
        total_vuln_dict.flatten!

        while more_records
          issues = client.get_vulnerabilities(count: @batch_size, page: page)
          more_records = issues["next"].present?

          issues["results"].foreach do |issue|
            asset = extract_asset(issue)
            # Extract vuln
            vuln = extract_vuln(issue)
            vuln_dict_detail = total_vuln_dict.find { |a| a["id_ddi"] == issue["id_ddi"] }
            definition = extract_definition(issue, vuln_dict_detail)
            # Use #create_kdi_asset_vuln for vulnerabilities or create_kdi_asset_finding for findings
            create_kdi_asset_vuln(asset, vuln)

            # create the KDI vuln def entry
            create_kdi_vuln_def(definition)
          end

          kdi_upload(@output_directory, "digital_#{batch_count}_defense.json", @kenna_connector_id, @kenna_api_host, @kenna_api_key, @skip_autoclose, @retries, @kdi_version)

          page += 1
          batch_count += 1 if more_records.present?
        end

        kdi_connector_kickoff(@kenna_connector_id, @kenna_api_host, @kenna_api_key)
      rescue Kenna::128iid::DigitalDefense::Client::ApiError => e
        fail_task e.message
      end

      private

      def initialize_options
        @host = @options[:digital_defense_api_host]
        @api_token = @options[:digital_defense_api_token]
        @output_directory = @options[:output_directory]
        @kenna_api_host = @options[:kenna_api_host]
        @kenna_api_key = @options[:kenna_api_key]
        @kenna_connector_id = @options[:kenna_connector_id]
        @batch_size = @options[:batch_size].to_i
        @skip_autoclose = false
        @retries = 3
        @kdi_version = 2
      end

      def extract_asset(issue)
        asset = {
          "ip_address" => issue.fetch("ip_address"),
          "external_id" => issue.fetch("active_view_host_id").to_s
        }.tap do |a|
          a["hostname"] = issue.fetch("hostname") if issue.fetch("ip_address") != issue.fetch("hostname")
        end
        # in case any values are nil, it's good to remove them
        asset.compact
      end

      def extract_vuln(issue)
        vuln = {
          "scanner_identifier" => issue.fetch("id"),
          "vuln_def_name" => issue.fetch("title"),
          "status" => STATUS[issue.fetch("active_view_status")], # TODO: Need to check
          "scanner_type" => "Digital Defense",
          "scanner_score" => issue.fetch("active_view_active_risk_score").to_i / 10,
          "created_at" => issue.fetch("active_view_date_first_created"),
          "details" => JSON.pretty_generate(extract_additional_fields(issue))
        }.tap do |v|
          v["port"] = issue.fetch("port") if issue.fetch("port").positive? && issue.fetch("port").to_i <= 65_535
        end

        vuln.compact
      end

      def extract_definition(issue, vuln_dict)
        definition = {
          "scanner_type" => "Digital Defense",
          "name" => issue.fetch("title"),
          "description" => vuln_dict["details"]["vulnerability_details"]["value"],
          "solution" => vuln_dict["details"]["solution_details"]["value"]
        }.tap do |ed|
          ed["cve_identifiers"] = vuln_dict["summary"]["cves"].join(",") if vuln_dict["summary"]["cves"].present?
        end
        # in case any values are null, it's good to remove them
        definition.compact
      end

      def extract_additional_fields(issue)
        additional_fields = {
          "transport" => issue.fetch("transport"),
          "protocol" => issue.fetch("protocol"),
          "tunnel" => issue.fetch("tunnel"),
          "active_view_active_risk_score" => issue.fetch("active_view_active_risk_score"),
          "severities" => issue.fetch("severities"),
          "hidden" => issue.fetch("hidden"),
          "host_hidden" => issue.fetch("host_hidden"),
          "data" => issue.fetch("data"),
          "manually_added" => issue.fetch("manually_added"),
          "false_positive" => issue.fetch("false_positive"),
          "date_started" => issue.fetch("date_started"),
          "date_finished" => issue.fetch("date_finished"),
          "hide_from_now_on" => issue.fetch("hide_from_now_on"),
          "detect_type" => issue.fetch("detect_type"),
          "vuln_class" => issue.fetch("vuln_class"),
          "scanner_version" => issue.fetch("scanner_version"),
          "matched_status" => issue.fetch("matched_status"),
          "cvss_score" => issue.fetch("cvss_score"),
          "cvss_version" => issue.fetch("cvss_version"),
          "cvss_base_score_v2" => issue.fetch("cvss_base_score_v2"),
          "cvss_base_score_v3" => issue.fetch("cvss_base_score_v3"),
          "has_notes" => issue.fetch("has_notes"),
          "labels" => issue.fetch("labels")
        }.tap do |eaf|
          eaf["port"] = issue.fetch("port") if issue.fetch("port").positive? && issue.fetch("port").to_i >= 65_535
        end

        additional_fields.compact
      end
    end
  end
end
