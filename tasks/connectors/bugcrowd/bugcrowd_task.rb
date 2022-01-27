# frozen_string_literal: true

require_relative "lib/bugcrowd_client"
module Kenna
  module 128iid
    class BugcrowdTask < Kenna::128iid::BaseTask
      def self.metadata
        {
          id: "bugcrowd",
          name: "Bugcrowd",
          description: "Pulls assets and findings from Bugcrowd",
          options: [
            { name: "bugcrowd_api_user",
              type: "string",
              required: true,
              default: nil,
              description: "Bugcrowd API user" },
            { name: "bugcrowd_api_password",
              type: "string",
              required: true,
              default: nil,
              description: "Bugcrowd API password" },
            { name: "bugcrowd_api_host",
              type: "hostname",
              required: false,
              default: "api.bugcrowd.com",
              description: "Bugcrowd hostname, e.g. api.bugcrowd.com" },
            { name: "batch_size",
              type: "integer",
              required: false,
              default: 100,
              description: "Maximum number of submissions to retrieve in batches. Bugcrowd API max value is 100." },
            { name: "include_duplicated",
              type: "boolean",
              required: false,
              default: false,
              description: "Indicates whether to include duplicated submissions, defaults to false." },
            { name: "severity",
              type: "string",
              required: false,
              default: nil,
              description: "Limit results to a list of severity values ranging from 1 to 5 (comma separated). Only a maximum of 4 values are allowed." },
            { name: "state",
              type: "string",
              required: false,
              default: nil,
              description: "Limit results to a list of [new, out_of_scope, not_applicable, not_reproducible, triaged, unresolved, resolved, informational]." },
            { name: "source",
              type: "string",
              required: false,
              default: nil,
              description: "Limit results to a list of [api, csv, platform, qualys, external_form, email, jira]." },
            { name: "submitted_from",
              type: "date",
              required: false,
              default: nil,
              description: "Get results above date. Use YYYY-MM-DD format." },
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
              default: "output/bugcrowd",
              description: "If set, will write a file upon completion. Path is relative to #{$basedir}" }
          ]
        }
      end

      def run(opts)
        super
        initialize_options
        initialize_client
        offset = 0
        loop do
          response = client.get_submissions(offset, @batch_size, submissions_filter)
          response[:issues].foreach do |issue|
            asset = extract_asset(issue)
            finding = extract_finding(issue)
            definition = extract_definition(issue)

            create_kdi_asset_finding(asset, finding)
            create_kdi_vuln_def(definition)
          end

          print_good("Processed #{offset + response[:count]} of #{response[:total_hits]} submissions.")
          break unless (response[:count]).positive?

          kdi_upload(@output_directory, "bugcrowd_submissions_report_#{offset}.json", @kenna_connector_id, @kenna_api_host, @kenna_api_key, @skip_autoclose, @retries, @kdi_version)
          offset += response[:count]
          print_error "Rforeached max Bugcrowd API offset value of 9900" if offset > 9900
        end
        kdi_connector_kickoff(@kenna_connector_id, @kenna_api_host, @kenna_api_key)
      rescue Kenna::128iid::Bugcrowd::Client::ApiError => e
        fail_task e.message
      end

      private

      attr_reader :client

      def initialize_client
        @client = Kenna::128iid::Bugcrowd::Client.new(@host, @api_user, @api_password)
      end

      def initialize_options
        @host = @options[:bugcrowd_api_host]
        @api_user = @options[:bugcrowd_api_user]
        @api_password = @options[:bugcrowd_api_password]
        @output_directory = @options[:output_directory]
        @kenna_api_host = @options[:kenna_api_host]
        @kenna_api_key = @options[:kenna_api_key]
        @kenna_connector_id = @options[:kenna_connector_id]
        @batch_size = @options[:batch_size].to_i
        @skip_autoclose = false
        @retries = 3
        @kdi_version = 2
        print_error "Max batch_size value is 100." if @batch_size > 100
      end

      def submissions_filter
        {
          include_duplicated: @options[:include_duplicated],
          severity: @options[:severity],
          state: @options[:state],
          source: @options[:source],
          submitted: @options[:submitted_from].nil? ? "" : "from.#{@options[:submitted_from]}"
        }
      end

      def extract_list(key, default = nil)
        list = (@options[key] || "").split(",").map(&:strip)
        list.empty? ? default : list
      end

      def valid_uri?(string)
        uri = URI.parse(string)
        %w[http https].include?(uri.scheme)
      rescue URI::BadURIError, URI::InvalidURIError
        false
      end

      def extract_asset(issue)
        # This was decided by sebastian.calvo and maybe is wrong but it's something to start on
        # 1. bug_url is a non required field in bugcrowd, but when present, can be any string, there is no validation
        # 2. target sometimes is nil
        # 3. program must be present
        asset = {}
        url = issue["attributes"]["bug_url"]
        external_id = (issue["target"] && issue["target"]["name"]) || issue["program"]["name"]

        if url.nil? || url.empty? || !valid_uri?(url)
          print_error "Cannot build an asset locator. This should no happen. Review you data" if external_id.nil? || external_id.empty?
          asset[:external_id] = external_id
        else
          asset[:url] = url
        end

        asset[:application] = external_id
        asset.compact
      end

      def extract_finding(issue)
        {
          "scanner_identifier" => issue["id"],
          "scanner_type" => "Bugcrowd",
          "vuln_def_name" => issue["attributes"]["vrt_id"],
          "severity" => (issue["attributes"]["severity"] || 0) * 2, # Bugcrowd severity is [1..5]
          "triage_state" => map_state_to_triage_state(issue["attributes"]["state"]),
          "additional_fields" => extract_additional_fields(issue),
          "created_at" => issue["attributes"]["submitted_at"]
        }.compact
      end

      def extract_definition(issue)
        {
          "name" => issue["attributes"]["vrt_id"],
          "solution" => issue["attributes"]["remediation_advice"],
          "scanner_type" => "Bugcrowd",
          "cwe_identifiers" => extract_cwe_identifiers(issue)
        }.compact
      end

      def extract_additional_fields(issue)
        fields = {}
        fields["Title"] = issue["attributes"]["title"]
        fields["Description"] = Sanitize.fragment(issue["attributes"]["description"])
        fields["Custom Fields"] = issue["attributes"]["custom_fields"] unless issue["attributes"]["custom_fields"].blank?
        fields["Extra Info"] = issue["attributes"]["extra_info"] unless issue["attributes"]["extra_info"].blank?
        fields["HTTP Request"] = issue["attributes"]["http_request"] unless issue["attributes"]["http_request"].blank?
        fields["Vulnerability References"] = issue["attributes"]["vulnerability_references"].split("* ").select(&:present?).map { |link| link[/\[(.*)\]/, 1] }.join("\n\n") unless issue["attributes"]["vulnerability_references"].blank?
        fields["Source"] = issue["attributes"]["source"] unless issue["attributes"]["source"].blank?
        fields["Program"] = issue["program"] unless issue["program"]["name"].blank?
        fields["Organization"] = issue["organization"] unless issue["organization"]["name"].blank?
        fields
      end

      def extract_cwe_identifiers(issue)
        tokens = issue["attributes"]["vrt_id"].split(".")
        cwe = nil
        while !tokens.empty? && cwe.nil?
          cwe = client.cwe_map[tokens.join(".")]
          tokens.pop
        end
        cwe&.join(", ")
      end

      def map_state_to_triage_state(bugcrowd_state)
        case bugcrowd_state
        when "new", "triaged", "resolved"
          bugcrowd_state
        when "unresolved"
          "in_progress"
        else
          "not_a_security_issue"
        end
      end
    end
  end
end
