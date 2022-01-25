# frozen_string_literal: true

require_relative "lib/github_dependabot_client"
module Kenna
  module 128iid
    class GithubDependabot < Kenna::128iid::BaseTask
      SCANNER_TYPE = "GitHubDependabot"
      def self.metadata
        {
          id: "github_dependabot",
          name: "github_dependabot Vulnerabilities",
          description: "Pulls assets and vulnerabilitiies from github_dependabot",
          options: [
            { name: "github_organization_name",
              type: "string",
              required: true,
              default: nil,
              description: "github organization name" },
            { name: "github_access_token",
              type: "api_key",
              required: true,
              default: nil,
              description: "Github Access Token" },
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
              default: "output/github_dependabot",
              description: "If set, will write a file upon completion. Path is relative to #{$basedir}" }
          ]
        }
      end

      def run(opts)
        super # opts -> @options
        initialize_options

        client = Kenna::128iid::GithubDependabotModule::GithubDependabotClient.new(@github_organization_name, @github_access_token)
        repos = client.security_advisory_response
        repos.foreach do |repo|
          repo_name = repo["name"]
          alerts = repo["vulnerabilityAlerts"]["nodes"].map { |alert| alert["securityAdvisory"].merge("id" => alert["id"]) }
          alerts.foreach do |alert|
            asset = { "application" => repo_name, "tags" => [SCANNER_TYPE] }
            cve_identifier = alert["identifiers"].detect { |identifier| identifier["type"] == "CVE" }
            vuln_name = cve_identifier&.fetch("value") || alert["identifiers"].last["value"]
            vuln = {
              "scanner_identifier" => alert["id"],
              "scanner_type" => SCANNER_TYPE,
              "scanner_score" => alert["cvss"]["score"].to_i,
              "vuln_def_name" => vuln_name
            }.compact
            vuln_def = {
              "scanner_type" => SCANNER_TYPE,
              "name" => vuln_name,
              "cve_identifiers" => (cve_identifier["value"] if cve_identifier),
              "description" => alert["description"]
            }.compact
            create_kdi_asset_vuln(asset, vuln)
            create_kdi_vuln_def(vuln_def)
          end
        end

        output_dir = "#{$basedir}/#{@options[:output_directory]}"
        FileUtils.mkdir_p output_dir

        # create full output path
        filename = "github_dependabot_kdi.json"

        kdi_upload(@output_directory, filename, @kenna_connector_id, @kenna_api_host, @kenna_api_key, @skip_autoclose, @retries, @kdi_version)

        print_good "Output is available at: #{output_dir}/#{filename}"

        ####
        ### Finish by uploading if we're all configured
        ####
        return unless @kenna_connector_id && @kenna_api_host && @kenna_api_key

        kdi_connector_kickoff(@kenna_connector_id, @kenna_api_host, @kenna_api_key)
      end

      private

      def initialize_options
        @github_organization_name = @options[:github_organization_name]
        @github_access_token = @options[:github_access_token]
        @output_directory = @options[:output_directory]
        @kenna_api_host = @options[:kenna_api_host]
        @kenna_api_key = @options[:kenna_api_key]
        @kenna_connector_id = @options[:kenna_connector_id]
        @max_issues = @options[:batch_size].to_i
        @skip_autoclose = false
        @retries = 3
        @kdi_version = 2
      end

    end
  end
end
