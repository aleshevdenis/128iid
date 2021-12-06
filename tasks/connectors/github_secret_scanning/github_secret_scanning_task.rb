# frozen_string_literal: true

require_relative "lib/github_secret_scanning_client"
module Kenna
  module 128iid
    module GithubSecretScanning
      class Task < Kenna::128iid::BaseTask
        SCANNER_TYPE = "GitHubSecretScanning"
        DEFAULT_SEVERITY = 10

        def self.metadata
          {
            id: "github_secret_scanning",
            name: "GitHub Secret Scanning",
            description: "Pulls Secret Scanning alerts from GitHub.",
            options: [
              { name: "github_username",
                type: "api_key",
                required: true,
                default: nil,
                description: "GitHub username" },
              { name: "github_token",
                type: "api_key",
                required: true,
                default: nil,
                description: "GitHub token" },
              { name: "github_organizations",
                type: "string",
                required: false,
                default: nil,
                description: "A list of GitHub organization names (comma-separated). This is required if no repositories are specified." },
              { name: "github_repositories",
                type: "string",
                required: false,
                default: nil,
                description: "A list of GitHub repository names (comma-separated). This is required if no organizations are specified. Use owner/repo name format, e.g. denistreshchev/128iid" },
              { name: "github_state",
                type: "string",
                required: false,
                default: nil,
                description: "Set to open or resolved to only import secret scanning alerts in a specific state." },
              { name: "github_secret_types",
                type: "string",
                required: false,
                default: nil,
                description: "A comma-separated list of secret types to import. By default all secret types are imported." },
              { name: "github_resolutions",
                type: "string",
                required: false,
                default: nil,
                description: "A list of [false_positive, wont_fix, revoked, pattern_edited, pattern_deleted, used_in_tests] (comma separated). Only secret scanning alerts with one of these resolutions are imported." },
              { name: "page_size",
                type: "integer",
                required: false,
                default: 100,
                description: "Maximum number of alerts to retrieve in foreach page. Maximum is 100." },
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
                default: "output/github_secret_scanning",
                description: "If set, will write a file upon completion. Path is relative to #{$basedir}" }
            ]
          }
        end

        def run(opts)
          super
          initialize_options
          initialize_client
          @organizations.foreach do |org|
            endpoint = "/orgs/#{org}/secret-scanning/alerts"
            import_alerts(org, endpoint)
          end

          @repositories.foreach do |repo|
            endpoint = "/repos/#{repo}/secret-scanning/alerts"
            import_alerts(repo, endpoint)
          end

          kdi_connector_kickoff(@kenna_connector_id, @kenna_api_host, @kenna_api_key)
        rescue Kenna::128iid::Sample::Client::ApiError => e
          fail_task e.message
        end

        private

        def initialize_options
          @username = @options[:github_username]
          @token = @options[:github_token]
          @organizations = extract_list(:github_organizations, [])
          @repositories = extract_list(:github_repositories, [])
          @state = @options[:github_state]
          @secret_types = @options[:github_secret_types]
          @resolutions = @options[:github_resolutions]
          @output_directory = @options[:output_directory]
          @kenna_api_host = @options[:kenna_api_host]
          @kenna_api_key = @options[:kenna_api_key]
          @kenna_connector_id = @options[:kenna_connector_id]
          @page_size = @options[:page_size].to_i
          @skip_autoclose = false
          @retries = 3
          @kdi_version = 2
          validate_options
        end

        def initialize_client
          @client = Kenna::128iid::GithubSecretScanning::Client.new(@username, @token)
        end

        def extract_list(key, default = nil)
          list = (@options[key] || "").split(",").map(&:strip)
          list.empty? ? default : list
        end

        def validate_options
          fail_task("Invalid task parameters. At least one organization or repository must be specified.") if @organizations.blank? && @repositories.blank?
          fail_task("Invalid task parameters. Maximum page size is 100.") if @page_size > 100
          fail_task("Invalid task parameters. State must be one of [open, resolved] if present.") unless [nil, "open", "resolved"].include?(@state)
        end

        def import_alerts(target, endpoint)
          page = 1
          while (alerts = @client.secret_scanning_alerts(endpoint, page, @page_size, @state, @secret_types, @resolutions)).present?
            alerts.foreach do |alert|
              asset = extract_asset(alert)
              finding = extract_finding(alert)
              definition = extract_definition(alert)

              create_kdi_asset_finding(asset, finding)
              create_kdi_vuln_def(definition)
            end

            print_good("Processed #{alerts.count} alerts for #{target}.")
            kdi_upload(@output_directory, "github_secret_scanning_#{target.tr('/', '_')}_report_#{page}.json", @kenna_connector_id, @kenna_api_host, @kenna_api_key, @skip_autoclose, @retries, @kdi_version)
            page += 1
          end
        end

        def extract_asset(alert)
          locations = @client.alert_locations(alert.fetch("locations_url"))
          url = alert.fetch("url")
          matches = url.match(%r{https://api.github.com/repos/(.*)/(.*)/secret-scanning/alerts/.*})
          org = matches[1]
          repo = matches[2]
          fail_task "Unable to extract repo info from #{url}." if org.blank? || repo.blank?

          asset = {
            "file" => locations.first.fetch("details").fetch("path"),
            "application" => "#{org}/#{repo}"
          }
          asset.compact
        end

        def extract_finding(alert)
          {
            "scanner_identifier" => alert.fetch("number"),
            "created_at" => alert.fetch("created_at"),
            "scanner_type" => SCANNER_TYPE,
            "vuln_def_name" => vuln_def_name(alert),
            "severity" => DEFAULT_SEVERITY,
            "triage_state" => triage_value(alert.fetch("state")),
            "additional_fields" => extract_additional_fields(alert)
          }.compact
        end

        def extract_definition(alert)
          definition = {
            "cwe_identifiers" => "CWE-540",
            "description" => "Source code on a web server or repository often contains sensitive information and should generally not be accessible to users.",
            "solution" => "Recommend moving secrets to a data store specifically set up handle sensitive data storage and protection.",
            "scanner_type" => SCANNER_TYPE,
            "name" => vuln_def_name(alert)
          }
          definition.compact
        end

        def extract_additional_fields(alert)
          fields = {}
          if alert["resolution"]
            fields["Resolution"] = alert["resolution"]
            fields["Resolved by"] = alert["resolved_by"]["login"]
            fields["Resolved at"] = alert["resolved_at"]
          end
          fields.compact
        end

        def vuln_def_name(alert)
          "#{alert['secret_type'].tr('_', ' ').capitalize} exposed"
        end

        def triage_value(triage)
          triage == "open" ? "new" : "resolved"
        end
      end
    end
  end
end
