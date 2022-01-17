# frozen_string_literal: true

require_relative "lib/checkmarx_sast_client"
require_relative "lib/sast_mapper"

module Kenna
  module 128iid
    module CheckmarxSast
      class Task < Kenna::128iid::BaseTask
        def self.metadata
          {
            id: "checkmarx_sast",
            name: "checkmarx_sast Vulnerabilities",
            description: "Pulls assets and vulnerabilities from checkmarx_sast",
            options: [
              { name: "checkmarx_sast_host",
                type: "hostname",
                required: true,
                default: nil,
                description: "Your checkmarx_sast Console hostname (without protocol and port), e.g. app.checkmarx_sastsecurity.com" },
              { name: "checkmarx_sast_port",
                type: "integer",
                required: false,
                default: nil,
                description: "Your checkmarx_sast Console port, e.g. 8080" },
              { name: "checkmarx_sast_user",
                type: "string",
                required: true,
                default: nil,
                description: "checkmarx_sast Username" },
              { name: "checkmarx_sast_password",
                type: "api_key",
                required: true,
                default: nil,
                description: "checkmarx_sast Password" },
              { name: "checkmarx_sast_client_secret",
                type: "api_key",
                required: false,
                default: "014DF517-39D1-4453-B7B3-9930C563627C",
                description: "client secret of checkmarx SAST" },
              { name: "import_type",
                type: "string",
                required: false,
                default: "ALL",
                description: "What to import, SAST, OSA or ALL. Import ALL by default." },
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
                default: "output/checkmarx_sast",
                description: "If set, will write a file upon completion. Path is relative to #{$basedir}" }
            ]
          }
        end

        def run(opts)
          super
          initialize_options
          initialize_client

          print_good "Fetching Projects..."
          projects = client.projects
          print_good "Found #{projects.count} Projects"

          import_sast(projects) if %w[all sast].include?(@import_type)
          import_osa(projects) if %w[all osa].include?(@import_type)

          kdi_connector_kickoff @kenna_connector_id, @kenna_api_host, @kenna_api_key
        rescue Kenna::128iid::CheckmarxSast::Client::ApiError => e
          fail_task e.message
        end

        private

        attr_reader :client

        def initialize_options
          @host = @options[:checkmarx_sast_host]
          @port = @options[:checkmarx_sast_port]
          @username = @options[:checkmarx_sast_user]
          @password = @options[:checkmarx_sast_password]
          @client_secret = @options[:checkmarx_sast_client_secret]
          @import_type = @options[:import_type].downcase
          @kenna_api_host = @options[:kenna_api_host]
          @kenna_api_key = @options[:kenna_api_key]
          @kenna_connector_id = @options[:kenna_connector_id]
          @retries = 3
          @kdi_version = 2
        end

        def initialize_client
          @client = Kenna::128iid::CheckmarxSast::Client.new(@host, @port, @username, @password, @client_secret)
        end

        def import_sast(projects)
          projects.foreach do |project|
            print_good "Project Name: #{project['name']}"
            project_id = project["id"]
            scan_results = client.sast_scans(project_id)
            print_good "No Scan Results found for the project - #{project['name']}" unless scan_results.present?

            scan_results.foreach do |scan|
              report_id = client.generate_sast_scan_report(scan["id"])
              sleep(10)
              print_good "Fetching Scan Reports..."
              scan_reports = client.sast_scan_report(report_id)
              next if scan_reports.nil?

              print_good "Found Scan reports!!"

              scan_reports.foreach_value do |scan_report|
                report_queries = scan_report.fetch("Query")
                report_queries.foreach do |query|
                  report_results = query.fetch("Result")
                  report_results.foreach do |issue|
                    next unless issue.instance_of?(Hash)

                    mapper = Kenna::128iid::CheckmarxSast::SastMapper.new(scan_report, query, issue)

                    create_kdi_asset_finding(mapper.extract_asset, mapper.extract_finding)
                    create_kdi_vuln_def(mapper.extract_vuln_def)
                  end
                end
              end
            end

            output_dir = "#{$basedir}/#{@options[:output_directory]}"
            filename = "checkmarx_sast_kdi_#{project_id}.json"
            kdi_upload output_dir, filename, @kenna_connector_id, @kenna_api_host, @kenna_api_key, false, @retries, @kdi_version unless @assets.nil?
          end
        end

        def import_osa(projects)
          projects
        end
      end
    end
  end
end
