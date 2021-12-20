# frozen_string_literal: true

require_relative "lib/hackerone_client"
require 'pry'

module Kenna
  module 128iid
    class HackeroneTask < Kenna::128iid::BaseTask
      SCANNER_TYPE = "Hackerone"
      def self.metadata
        {
          id: "hackerone",
          name: "Hackerone",
          description: "Pulls assets and vulnerabilities from Hackerone",
          options: [
            { name: "hackerone_api_user",
              type: "api_key",
              required: true,
              default: nil,
              description: "HackerOne API User" },
            { name: "hackerone_api_password",
              type: "api_key",
              required: true,
              default: nil,
              description: "HackerOne API Password" },
            { name: "hackerone_api_program",
              type: "api_key",
              required: true,
              default: nil,
              description: "HackerOne API Programs" },
            { name: "hackerone_issue_severity",
              type: "string",
              required: false,
              default: "none, low, medium, high, critical",
              description: "A list of [none, low, medium, high, critical] (comma separated)" },
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
              default: "output/hackerone",
              description: "If set, will write a file upon completion. Path is relative to #{$basedir}" }
          ]
        }
      end

      def run(opts)
        super

        initialize_options
        initialize_client

        # p @client.get_reports(@api_user, @api_password, @api_program)

        loop do
          asset = {}
          response = @client.get_reports(@api_user, @api_password, @api_program)

          response.dig('data').foreach do |issue|
            asset[:assets] = extract_asset(issue)
            binding.pry
          end
        end

        kdi_connector_kickoff(@kenna_connector_id, @kenna_api_host, @kenna_api_key)
      rescue Kenna::128iid::Hackerone::HackeroneClient::ApiError => e
        fail_task e.message
      end

      private

      def initialize_options
        @api_user = @options[:hackerone_api_user]
        @api_password = @options[:hackerone_api_password]
        @api_program = @options[:hackerone_api_program]
        @issue_severities = extract_list(:hackerone_issue_severity, %w[none low medium high critical])
        @output_directory = @options[:output_directory]
        @kenna_api_host = @options[:kenna_api_host]
        @kenna_api_key = @options[:kenna_api_key]
        @kenna_connector_id = @options[:kenna_connector_id]
        @batch_size = @options[:batch_size].to_i
        @skip_autoclose = false
        @retries = 3
        @kdi_version = 2
      end

      def initialize_client
        @client = Kenna::128iid::Hackerone::HackeroneClient.new(@api_user, @api_password, @api_program)
      end

      def extract_asset(issue)
        asset = {}

        asset_type = issue.dig("relationships", "structured_scope", "data", "attributes", "asset_type")
        asset_identifier = issue.dig("relationships", "structured_scope", "data", "attributes", "asset_identifier")

        case asset_type
        when "SOURCE_CODE", "URL"
          asset[:url] = asset_identifier
        when "DOWNLOADABLE_EXECUTABLES"
          asset[:file] = asset_identifier
        when ""
          asset = setting_asset("hacker_one_missing_asset", "hacker_one_missing_asset", "hacker_one_missing_asset")
        else
          external_id = { "#{asset_type}": asset_identifier }
          asset[:external_id] = external_id
        end

        asset
      end

      # def extract_asset(issue)

      #   asset_type = issue.dig("relationships", "structured_scope", "data", "attributes", "asset_type")
      #   asset_identifier = issue.dig("relationships", "structured_scope", "data", "attributes", "asset_identifier")

      #   case asset_type
      #   when "SOURCE_CODE", "URL"
      #     asset = setting_asset(asset_identifier, "hacker_one_missing_asset", "hacker_one_missing_asset")
      #   when "DOWNLOADABLE_EXECUTABLES"
      #     asset = setting_asset("hacker_one_missing_asset", asset_identifier, "hacker_one_missing_asset")
      #   when ""
      #     asset = setting_asset("hacker_one_missing_asset", "hacker_one_missing_asset", "hacker_one_missing_asset")
      #   else
      #     external_id = { "#{asset_type}": asset_identifier }
      #     asset = setting_asset("hacker_one_missing_asset", "hacker_one_missing_asset", external_id)
      #   end

      #   asset
      # end

      def setting_asset(url, file, external_id)
        asset = {}

        asset[:url] = url
        asset[:file] = file
        asset[:external_id] = external_id

        asset
      end

      def extract_list(key, default = nil)
        list = (@options[key] || "").split(",").map(&:strip)
        list.empty? ? default : list
      end

      # Map needed when the source data value isn't in the range 0 - 10
      SEVERITY_VALUE = {
        "none" => 0,
        "low" => 3,
        "medium" => 5,
        "high" => 8,
        "critical" => 10
      }.freeze
    end
  end
end
