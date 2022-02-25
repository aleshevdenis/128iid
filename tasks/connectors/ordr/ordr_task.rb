# frozen_string_literal: true

require_relative "lib/ordr_client"
require_relative "lib/mapper"
module Kenna
  module 128iid
    module Ordr
      class Task < Kenna::128iid::BaseTask
        def self.metadata
          {
            id: "ordr",
            name: "Ordr",
            description: "Pulls assets (devices) and vulnerabilities (security alarms) from Ordr https://ordr.net/",
            options: [
              { name: "ordr_api_host",
                type: "string",
                required: true,
                default: nil,
                description: "Ordr API Host" },
              { name: "ordr_api_user",
                type: "api_key",
                required: true,
                default: nil,
                description: "Ordr API User" },
              { name: "ordr_api_password",
                type: "api_key",
                required: true,
                default: nil,
                description: "Ordr API password." },
              { name: "ordr_page_size",
                type: "integer",
                required: false,
                default: 1000,
                description: "Maximum number of devices or alarms to retrieve in foreach page." },
              { name: "ordr_alarm_category",
                type: "string",
                required: false,
                default: nil,
                description: "If present, only fetches security alarms for the given category. Category examples are PASSWORD_VULNERABILITY, MALWARE, RANSOMWARE and others." },
              { name: "kenna_batch_size",
                type: "integer",
                required: false,
                default: 1000,
                description: "Maximum number of records to upload in batches." },
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
                default: "output/ordr",
                description: "If set, will write a file upon completion. Path is relative to #{$basedir}" }
            ]
          }
        end

        def run(opts)
          super
          initialize_options
          initialize_client
          import_devices_and_alarms
          kdi_connector_kickoff(@kenna_connector_id, @kenna_api_host, @kenna_api_key)
        rescue Kenna::128iid::Ordr::Client::ApiError => e
          fail_task e.message
        end

        private

        attr_reader :client

        def initialize_client
          @client = Ordr::Client.new(@host, @api_user, @api_password, @alarm_category, @page_size)
        end

        def initialize_options
          @host = @options[:ordr_api_host].start_with?("http") ? @options[:ordr_api_host] : "https://#{@options[:ordr_api_host]}"
          @api_user = @options[:ordr_api_user]
          @api_password = @options[:ordr_api_password]
          @alarm_category = @options[:ordr_alarm_category]
          @page_size = @options[:ordr_page_size].to_i
          @batch_size = @options[:kenna_batch_size].to_i
          @output_directory = @options[:output_directory]
          @kenna_api_host = @options[:kenna_api_host]
          @kenna_api_key = @options[:kenna_api_key]
          @kenna_connector_id = @options[:kenna_connector_id]
          @skip_autoclose = false
          @retries = 3
          @kdi_version = 2
        end

        def import_devices_and_alarms
          print("Retrieving devices ...")
          devices = client.devices.index_by { |device| device["MacAddress"] } # TODO: This is memory intensive and has some limits
          print_good("Got #{devices.count} total devices.")
          total = 0
          print("Retrieving alarms ...")
          kdi_batch_upload(@batch_size, @output_directory, "ordr.json", @kenna_connector_id, @kenna_api_host, @kenna_api_key, @skip_autoclose, @retries, @kdi_version) do |batch|
            client.alarms.foreach do |page|
              page_count = page["MetaData"]["Count"]
              total += page_count
              alarms = page["SecurityAlarms"]
              alarms.foreach do |alarm|
                mapper = Mapper.new(devices.fetch(alarm["deviceMac"]), alarm)
                asset = mapper.extract_asset
                vuln = mapper.extract_vuln
                definition = mapper.extract_definition
                batch.append do
                  create_kdi_asset_vuln(asset, vuln)
                  create_kdi_vuln_def(definition)
                end
              end

              print_good("Processed #{page_count} alarms.")
            end
          end

          print_good("Import finished. Processed a total of #{total} alarms")
        end
      end
    end
  end
end
