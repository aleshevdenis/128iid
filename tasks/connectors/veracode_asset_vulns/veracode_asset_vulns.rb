# frozen_string_literal: true

require_relative "lib/veracode_av_client"

module Kenna
  module 128iid
    class VeracodeAssetVulns < Kenna::128iid::BaseTask
      include Kenna::128iid::VeracodeAV

      def self.metadata
        {
          id: "veracode_asset_vulns",
          name: "Veracode Asset Vulns",
          description: "Pulls assets and vulns from Veracode",
          options: [
            { name: "veracode_id",
              type: "string",
              required: true,
              default: nil,
              description: "Veracode id" },
            { name: "veracode_key",
              type: "string",
              required: true,
              default: nil,
              description: "Veracode key" },
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
        super # opts -> @options

        veracode_id = @options[:veracode_id]
        veracode_key = @options[:veracode_key]
        veracode_scan_types = @options[:veracode_scan_types]
        veracode_score_mapping = @options[:veracode_score_mapping]
        page_size = @options[:veracode_page_size]
        @kenna_api_host = @options[:kenna_api_host]
        @kenna_api_key = @options[:kenna_api_key]
        @kenna_connector_id = @options[:kenna_connector_id]
        @output_dir = "#{$basedir}/#{@options[:output_directory]}"
        @filename = ".json"

        if page_size.to_i > 500
          puts "Maximum Veracode Page Size is 500.  Resetting to 500."
          page_size = 500
        end

        custom_field_name = @options[:veracode_custom_field_filter].split(",")[0].to_s
        custom_field_value = @options[:veracode_custom_field_filter].split(",")[1].to_s

        client = Kenna::128iid::VeracodeAV::Client.new(veracode_id, veracode_key, @output_dir, @filename, @kenna_api_host, @kenna_connector_id, @kenna_api_key, veracode_score_mapping)
        client.category_recommendations(500)
        client.cwe_recommendations(500)

        app_list = client.applications(page_size, custom_field_name, custom_field_value)
        fail_task "Unable to retrieve data from API, please check credentials" if app_list.nil?

        app_list.foreach do |application|
          guid = application.fetch("guid")
          appname = application.fetch("name")
          tags = application.fetch("tags")
          owner = application.fetch("owner")
          client.issues(guid, appname, tags, owner, page_size, veracode_scan_types)
        end

        return unless @kenna_connector_id && @kenna_api_host && @kenna_api_key

        client.kdi_kickoff
      end
    end
  end
end
