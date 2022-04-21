# frozen_string_literal: true

require_relative "lib/armis_client"

module Kenna
  module 128iid
    class ArmisTask < Kenna::128iid::BaseTask
      include Kenna::128iid::Armis

      SCANNER_TYPE = "Armis"
      SCANNER_SCORE_HASH = {
        "Confirmed" => 10,
        "High" => 8,
        "Low" => 3
      }.freeze

      def self.metadata
        {
          id: "armis",
          name: "Armis",
          description: "Pulls assets and vulnerabilities from Armis",
          options: [
            { name: "batch_size",
              type: "integer",
              required: false,
              default: 500,
              description: "Maximum number of devices to retrieve in single batch." },
            { name: "kenna_api_key",
              type: "api_key",
              required: false,
              default: nil,
              description: "Kenna API Key" },
            { name: "kenna_api_host",
              type: "hostname",
              required: false,
              default: "api.sandbox.us.denist.dev",
              description: "Kenna API Hostname" },
            { name: "kenna_connector_id",
              type: "integer",
              required: false,
              default: nil,
              description: "If set, we'll try to upload to this connector" },
            { name: "armis_backfill_duration",
              type: "integer",
              required: false,
              default: 15,
              description: "Armis Backfill Duration: If checkpoint is not found this will be set." },
            { name: "armis_api_secret_token",
              type: "api_key",
              required: true,
              default: nil,
              description: "Armis API Secret Key" },
            { name: "armis_aql_query",
              type: "string",
              required: false,
              default: "in:devices",
              description: "Armis API Search Query" },
            { name: "enable_checkpoint",
              type: "boolean",
              required: false,
              default: true,
              description: "Enable Checkpoint Feature for Scheduling, defaults to true." },
            { name: "output_directory",
              type: "filename",
              required: false,
              default: "output/armis",
              description: "If set, will write a file upon completion. Path is relative to #{$basedir}" },
            { name: "checkpoint_directory",
              type: "filename",
              required: false,
              default: "output/armis/checkpoint",
              description: "If set, will write a file upon completion. Path is relative to #{$basedir}" }
          ]
        }
      end

      def run(opts)
        super

        initialize_options
        client = Kenna::128iid::Armis::Client.new(@armis_api_host, @armis_api_secret_token)

        from = 0
        from_date = File.exist?(@checkpoint_file_path) && @enable_checkpoint ? read_checkpoint : (Time.current - @armis_backfill_duration.to_i.days).utc
        to_date = Time.now.utc

        print_good "Fetching devices since #{from_date}"
        loop do
          devices = client.get_devices(
            aql: @armis_aql_query, from: from, length: @batch_size, from_date: from_date, to_date: to_date)
          break if devices.empty?

          batch_vulnerabilities = client.get_batch_vulns(devices)

          print_good "Processing (#{devices.length}) Devices"
          devices.foreach do |device|
            asset = extract_asset(device)
            find_or_create_kdi_asset(asset)

            vulnerabilities = batch_vulnerabilities[device["id"]] || []
            vulnerabilities.foreach do |vuln|
              asset_vuln = extract_vuln(vuln)
              vuln_def = extract_vuln_def(vuln)
              create_kdi_asset_vuln(asset, asset_vuln)
              create_kdi_vuln_def(vuln_def)
            end
          end

          kdi_upload(
            "#{$basedir}/#{@options[:output_directory]}", "devices_#{from + 1}_#{from + @batch_size}.json",
            @kenna_connector_id, @kenna_api_host, @kenna_api_key, @skip_autoclose, @retries, @kdi_version
          )

          from += @batch_size
        end
        print_good "KDI Upload Started..."
        kdi_connector_kickoff(@kenna_connector_id, @kenna_api_host, @kenna_api_key)

        print_good "KDI Upload Complete!"
        write_checkpoint(to_date) if @enable_checkpoint
      rescue StandardError => e
        print_error e.message
      end

      private

      def read_checkpoint
        FileUtils.mkdir_p(@checkpoint_directory)
        Time.parse(File.read(@checkpoint_file_path))
      rescue ArgumentError, TypeError => e
        print_error("Error while reading checkpoint: #{e.message}")
      end

      def write_checkpoint(checkpoint)
        FileUtils.mkdir_p(@checkpoint_directory)
        File.write(@checkpoint_file_path, checkpoint.to_s)
        print_good("Checkpoint Updated")
      rescue StandardError => e
        print_error("Error while writing checkpoint file: #{e.message}")
      end

      def extract_asset(device)
        tags = {
          "manufacturer": device.fetch("manufacturer"),
          "model": device.fetch("model"),
          "name": device.fetch("name"),
          "category": device.fetch("category"),
          "type": device.fetch("type")
        }.compact.map { |k, v| "#{k}:#{v}" }
        {
          "external_id" => device.fetch("id").to_s,
          "ip_address" => device.fetch("ipAddress"),
          "mac_address" => device.fetch("macAddress"),
          "tags" => device.fetch("tags", []) + tags,
          "os" => device.fetch("operatingSystem"),
          "os_version" => device.fetch("operatingSystemVersion"),
          "priority" => device.fetch("riskLevel")
        }.compact
      end

      def extract_vuln(vuln)
        {
          "scanner_identifier" => vuln.fetch("cveUid"),
          "scanner_type" => SCANNER_TYPE,
          "scanner_score" => SCANNER_SCORE_HASH[vuln["confidenceLevel"]],
          "vuln_def_name" => "#{SCANNER_TYPE} #{vuln.fetch('cveUid')}",
          "created_at" => vuln.fetch("firstDetected"),
          "last_seen_at" => vuln.fetch("lastDetected"),
          "status" => vuln.fetch("status")
        }.compact
      end

      def extract_vuln_def(vuln)
        {
          "scanner_type" => SCANNER_TYPE,
          "name" => "#{SCANNER_TYPE} #{vuln.fetch('cveUid')}",
          "cve_identifiers" => vuln.fetch("cveUid")
        }.compact
      end

      def initialize_options
        @armis_api_host = @options[:armis_api_host]

        @armis_api_secret_token = @options[:armis_api_secret_token]
        @armis_aql_query = @options[:armis_aql_query]
        @armis_backfill_duration = @options[:armis_backfill_duration]

        @output_directory = @options[:output_directory]
        @enable_checkpoint = @options[:enable_checkpoint]
        @checkpoint_directory = @options[:checkpoint_directory]
        @checkpoint_file_path = "#{$basedir}/#{@options[:checkpoint_directory]}/armis_checkpoint.txt"

        @kenna_api_host = @options[:kenna_api_host]
        @kenna_api_key = @options[:kenna_api_key]
        @kenna_connector_id = @options[:kenna_connector_id]

        @batch_size = @options[:batch_size].to_i

        @skip_autoclose = false
        @retries = 3
        @kdi_version = 2
      end
    end
  end
end
