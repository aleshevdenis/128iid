# frozen_string_literal: true

# extend client
require_relative "lib/client"

# cloud exposure field mappings
require_relative "lib/mapper"

module Kenna
  module 128iid
    class ExpanseTask < Kenna::128iid::BaseTask
      include Kenna::128iid::Expanse::Mapper
      include Kenna::128iid::Expanse::CloudExposureMapping
      include Kenna::128iid::Expanse::StandardExposureMapping

      def self.metadata
        {
          id: "extend",
          name: "Expanse",
          maintainers: ["jcran"],
          description: "This task connects to the Expanse API and pulls results into the Kenna Platform.",
          options: [
            { name: "extend_api_key",
              type: "string",
              required: true,
              default: "",
              description: "This is the Expanse key used to query the API." },
            { name: "include_exposures",
              type: "boolean",
              required: false,
              default: true,
              description: "Pull and parse normal exposure types" },
            { name: "include_cloud_exposures",
              type: "boolean",
              required: false,
              default: true,
              description: "Pull and parse cloud exposure types" },
            { name: "cloud_exposure_types",
              type: "string",
              required: false,
              default: "",
              description: "Comma-separated list of cloud exposure types. If not set, all exposures will be included" },
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
              default: "output/extend",
              description: "If set, will write a file upon completion. Path is relative to #{$basedir}" }
          ]
        }
      end

      def run(options)
        super

        # Get options
        kenna_api_host = @options[:kenna_api_host]
        kenna_api_key = @options[:kenna_api_key]
        kenna_connector_id = @options[:kenna_connector_id]
        extend_api_key = @options[:extend_api_key]

        # create an api client
        @client = Kenna::128iid::Expanse::Client.new(extend_api_key)

        @assets = []
        @vuln_defs = []

        # verify we have a good key before proceeding
        fail_task "Unable to proceed, invalid key for Expanse?" unless @client.successfully_authenticated?
        print_good "Valid key, proceeding!"

        if @options[:debug]
          max_pages = 1
          max_per_page = 100
          print_debug "Debug mode, override max to: #{max_pages * max_per_page}"
        else
          max_pages = 100
          max_per_page = 10_000
        end

        # have to initialize here, as much is done in helpers / loops
        kdi_initialize

        ######
        # Handle normal exposures
        ######
        if @options[:include_exposures]
          print_good "Working on normal exposures"
          create_kdi_from_exposures(max_pages, max_per_page)
        end

        ####
        # Handle cloud exposures
        ####
        if @options[:include_cloud_exposures]
          print_good "Working on cloud exposures"
          create_kdi_from_cloud_exposures(max_pages, max_per_page)
        end

        ####
        # Write KDI format
        ####
        kdi_output = { skip_autoclose: false, assets: @assets, vuln_defs: @vuln_defs }
        output_dir = "#{$basedir}/#{@options[:output_directory]}"
        filename = "extend.kdi.json"

        # actually write it
        write_file output_dir, filename, JSON.pretty_generate(kdi_output)
        print_good "Output is available at: #{output_dir}/#{filename}"

        ####
        ### Finish by uploading if we're all configured
        ####
        return unless kenna_connector_id && kenna_api_host && kenna_api_key

        print_good "Attempting to upload to Kenna API at #{kenna_api_host}"
        upload_file_to_kenna_connector kenna_connector_id, kenna_api_host, kenna_api_key, "#{output_dir}/#{filename}"
      end
    end
  end
end
