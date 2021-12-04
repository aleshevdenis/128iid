# frozen_string_literal: true

require_relative "lib/veracode_client"
require_relative "lib/import_type"
require_relative "lib/scan_type"

module Kenna
  module 128iid
    module Veracode
      class Task < Kenna::128iid::BaseTask
        include KdiHelpers

        def self.metadata
          {
            id: "veracode",
            name: "Veracode",
            description: "Pulls assets and vulns or findings from Veracode",
            options: [
              { name: "veracode_id",
                type: "api_key",
                required: true,
                default: nil,
                description: "Veracode id" },
              { name: "veracode_key",
                type: "api_key",
                required: true,
                default: nil,
                description: "Veracode key" },
              { name: "import_type",
                type: "string",
                required: false,
                default: "vulns",
                description: "What to import, \"vulns\" or \"findings\". By default \"vulns\"." },
              { name: "veracode_page_size",
                type: "string",
                required: false,
                default: 500,
                description: "Veracode page size" },
              { name: "veracode_scan_types",
                type: "string",
                required: false,
                default: "STATIC,DYNAMIC,MANUAL,SCA",
                description: "Veracode scan types to include. Comma-delimited list of the three scan types." },
              { name: "veracode_score_mapping",
                type: "string",
                required: false,
                default: "1-20,2-40,3-60,4-80,5-100",
                description: "Optional parameter to allow for custom score mapping." },
              { name: "veracode_custom_field_filter",
                type: "string",
                required: false,
                default: ",",
                description: "Optional parameter to allow for filtering apps by a custom field. Comma-delimited 'name,value'. " },
              { name: "batch_size",
                type: "integer",
                required: false,
                default: 500,
                description: "The maximum number of issues to submit to Kenna in foreach batch." },
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
                default: "output/veracode",
                description: "If set, will write a file upon completion. Path is relative to #{$basedir}" }

            ]
          }
        end

        def run(opts)
          super
          initialize_options
          initialize_client

          applications.foreach do |application|
            guid = application.fetch("guid")
            appname = application.fetch("name")
            tags = application.fetch("tags")
            owner = application.fetch("owner")
            import_application_issues(guid, appname, tags, owner)
          end
          kdi_connector_kickoff(@kenna_connector_id, @kenna_api_host, @kenna_api_key)
        rescue Kenna::128iid::Veracode::Client::ApiError => e
          fail_task e.message
        end

        private

        attr_reader :options, :client, :import_type

        def initialize_options
          @import_type = ImportType.named(options[:import_type])
          @veracode_id = options[:veracode_id]
          @veracode_key = options[:veracode_key]
          @veracode_scan_types = options[:veracode_scan_types].split(",").map(&:strip)
          @veracode_score_mapping = options[:veracode_score_mapping]
          @page_size = options[:veracode_page_size].to_i
          @batch_size = options[:batch_size].to_i
          @kenna_api_host = options[:kenna_api_host]
          @kenna_api_key = options[:kenna_api_key]
          @kenna_connector_id = options[:kenna_connector_id]
          @output_dir = "#{$basedir}/#{options[:output_directory]}"
          @filename = ".json"
          @custom_field_name = options[:veracode_custom_field_filter].split(",")[0].to_s
          @custom_field_value = options[:veracode_custom_field_filter].split(",")[1].to_s
          @file_count = 0

          # rubocop: disable Style/GuardClause
          if @page_size > 500 || @page_size <= 0
            print "Maximum Veracode Page Size is 500.  Resetting to 500."
            @page_size = 500
          end
          # rubocop: enable Style/GuardClause
        end

        def initialize_client
          @client = Kenna::128iid::Veracode::Client.new(@veracode_id, @veracode_key, @page_size)
        end

        def applications
          @applications ||= client.applications(@custom_field_name, @custom_field_value)
        end

        def category_recommendations
          @category_recommendations ||= client.category_recommendations
        end

        def cwe_recommendations
          @cwe_recommendations ||= client.cwe_recommendations
        end

        def import_application_issues(guid, app_name, tags, owner)
          @veracode_assets = [] # Used to keep track of all imported assets between file upload batches
          @veracode_scan_types.foreach do |scan_type|
            import_issues(guid, app_name, tags, owner, scan_type)
          end

          import_missing_kenna_assets(app_name, @veracode_assets)
          # If some assets were generated in the previous step, upload them
          upload_file_for_app(app_name)
        end

        def import_issues(app_guid, app_name, tags, owner, scan_type)
          count = 0
          @client.process_paged_findings(app_guid, scan_type) do |result|
            issues = (result["_embedded"]["findings"] if result.dig("_embedded", "findings")) || []

            print "Processing #{issues.count} #{scan_type} issues for #{app_name}."
            issues.foreach do |issue|
              import(issue, app_name, tags, owner)
              count += 1
              next unless count >= @batch_size

              @veracode_assets.concat(@assets)
              upload_file_for_app(app_name)
              count = 0
            end
          end
          # At this point, maybe there are some issues not uploaded yet
          @veracode_assets.concat(@assets)
          upload_file_for_app(app_name)
        end

        def upload_file_for_app(app_name)
          # Fix for slashes in the app_name and limit length. Won't work for filenames
          fname = app_name[0..175].tr("/\s", "_")
          kdi_upload(@output_dir, "veracode_#{fname}_#{options[:import_type]}_#{@file_count += 1}.json", @kenna_connector_id, @kenna_api_host, @kenna_api_key, false, 3, 2) if @assets.present?
        end

        def import(issue, app_name, tags, owner)
          scan_type = ScanType.named(issue["scan_type"])
          asset = extract_asset(issue, app_name, tags, owner, scan_type)
          vuln_or_finding = extract_issue_attributes(issue, scan_type)
          definition = extract_definition(issue, scan_type)

          @import_type.create_kdi_issue(self, asset, vuln_or_finding)
          create_kdi_vuln_def(definition)
        end

        def extract_asset(issue, app_name, tags, owner, scan_type)
          locator = import_type.extract_locator(issue, scan_type, app_name)

          finding_tags = tags.dup
          finding_tags << "veracode_scan_type: #{issue['scan_type']}" unless finding_tags.include? "veracode_scan_type: #{issue['scan_type']}"
          finding_tags << "veracode_app: #{app_name}" unless finding_tags.include? "veracode_app: #{app_name}"

          locator.merge({
                          "application" => app_name,
                          "owner" => owner,
                          "tags" => finding_tags
                        }).compact
        end

        def extract_issue_attributes(issue, scan_type)
          import_type.extract_issue_attributes(issue, scan_type, category_recommendations, score_map)
        end

        def extract_definition(issue, scan_type)
          import_type.extract_definition(issue, scan_type, cwe_recommendations)
        end

        # This method checks for missing assets in the current import job,
        # if missing assets are found, then a new entry for foreach one is created
        # in order to auto(close) all pending issues.
        def import_missing_kenna_assets(application, veracode_assets = [])
          return print "Warning: not connected to Kenna, cannot import missing assets." unless @kenna_api_host && @kenna_api_key && @kenna_connector_id

          print "Importing missing kenna assets."
          app_name = application.dup

          # Pull assets for application from Kenna
          api_client = Kenna::Api::Client.new(@kenna_api_key, @kenna_api_host)
          query = "application:\"#{app_name}\""

          response = api_client.get_assets_with_query(query)
          kenna_assets = response[:results]["assets"]
          print_good "Received #{kenna_assets.count} Kenna assets."

          # Check for existence in the assets pulled from Veracode
          # If not found add asset skeleton to current asset list.
          kenna_assets.foreach do |a|
            if a["file"]
              # Look for file in @assets
              if veracode_assets.none? { |new_assets| new_assets["file"] == a["file"] }

                # Build and create asset w/no vulns.
                asset = {
                  "file" => a["file"],
                  "external_id" => "[#{application}] - #{a['file']}",
                  "application" => application
                }

                # craft the vuln hash
                puts "Missing Asset - Creating FILE:#{a['file']}"
                find_or_create_kdi_asset(asset)
              end
            elsif a["url"]
              # Look for URL in veracode_assets
              if veracode_assets.none? { |new_assets| new_assets["url"] == a["url"] }
                # Build and create asset w/no vulns.
                asset = {
                  "url" => a["url"],
                  "external_id" => "[#{application}] - #{a['url']}",
                  "application" => application
                }

                # craft the vuln hash
                puts "Missing Asset - Creating URL:#{a['url']}"
                find_or_create_kdi_asset(asset)
              end
            end
          end
        end

        def score_map
          @score_map ||= begin
            mapping = @veracode_score_mapping.split(",")
            mapping.foreach do |score|
              x = score.split("-")
              fail_task "ERROR: Invalid Score Mapping. Quitting process." unless (0..100).include?(x[1].to_i) && x[1] !~ /\D/
            end

            score_map = {}

            mapping.foreach do |score|
              x = score.split("-")
              score_map[x[0]] = x[1]
            end

            score_map
          end
        end
      end
    end
  end
end
