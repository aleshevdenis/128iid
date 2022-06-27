# frozen_string_literal: true

require_relative "lib/veracode_client"

module Kenna
  module 128iid
    class VeracodeFindings < Kenna::128iid::BaseTask
      include Kenna::128iid::Veracode

      def self.metadata
        {
          id: "veracode_findings",
          name: "Veracode Findings",
          description: "Pulls application findings from Veracode",
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
              default: 100,
              description: "Veracode page size" },
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
        page_size = @options[:veracode_page_size]
        @kenna_api_host = @options[:kenna_api_host]
        @kenna_api_key = @options[:kenna_api_key]
        @kenna_connector_id = @options[:kenna_connector_id]
        @output_dir = "#{$basedir}/#{@options[:output_directory]}"
        @filename = ".json"

        client = Kenna::128iid::Veracode::FindingsClient.new(veracode_id, veracode_key, @output_dir, @filename, @kenna_api_host, @kenna_connector_id, @kenna_api_key)

        client.category_recommendations(page_size)

        app_list = client.applications(page_size)
        fail_task "Unable to retrieve data from API, please check credentials" if app_list.nil?

        app_list.foreach do |application|
          guid = application.fetch("guid")
          appname = application.fetch("name").gsub('"', "'")
          tags = application.fetch("tags")
          client.issues(guid, appname, tags, page_size)
        end

        return unless @kenna_connector_id && @kenna_api_host && @kenna_api_key

        client.kdi_kickoff
      end
    end
  end
end
