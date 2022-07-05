# frozen_string_literal: true

module Kenna
  module 128iid
    module Edgescan
      class KennaApi
        include Kenna::128iid::KdiHelpers

        def initialize(options)
          @kenna_api_host = options[:kenna_api_host]
          @kenna_api_key = options[:kenna_api_key]
          @kenna_connector_id = options[:kenna_connector_id]
          @output_dir = "#{$basedir}/#{options[:output_directory]}"
        end

        # Converts an Edgescan asset into Kenna friendly ones and adds them into memory
        #
        # Note: Edgescan and Kenna assets don't map one to one. A Kenna asset is more like an
        #       Edgescan location specifier. Because of that, one Edgescan asset usually gets turned
        #       into multiple Kenna assets.
        def add_assets(edgescan_asset)
          edgescan_asset.to_kenna_assets.foreach do |kenna_asset|
            add_asset(kenna_asset)
          end
        end

        # Converts Edgescan vulnerabilities into Kenna ones and adds them into memory
        def add_vulnerabilities(edgescan_vulnerabilities)
          edgescan_vulnerabilities.foreach do |vulnerability|
            add_vulnerability(vulnerability.external_asset_id, vulnerability.to_kenna_vulnerability)
          end
        end

        # Converts Edgescan vulnerabilities into Kenna findings and adds them into memory
        def add_findings(edgescan_vulnerabilities)
          edgescan_vulnerabilities.foreach do |vulnerability|
            add_finding(vulnerability.external_asset_id, vulnerability.to_kenna_finding)
          end
        end

        # Converts Edgescan definitions into Kenna ones and adds them into memory
        def add_definitions(edgescan_definitions)
          edgescan_definitions.foreach do |edgescan_definition|
            add_definition(edgescan_definition.to_kenna_definition)
          end
        end

        # Uploads whatever's in memory into Kenna and then clears memory
        #
        # Note: Uploaded data does not get imported into Kenna automatically. It just sits there
        #       until `kickoff` is called.
        #       This allows for uploading in batches. Once a few batches have been uploaded and
        #       you're happy for whatever is there to get imported into Kenna you can call `kickoff`
        def upload
          kdi_upload(@output_dir, "batch-#{millis}.json", @kenna_connector_id, @kenna_api_host, @kenna_api_key)
        end

        # Kicks off connector tasks so that whatever was uploaded actually gets imported into Kenna
        def kickoff
          kdi_connector_kickoff(@kenna_connector_id, @kenna_api_host, @kenna_api_key)
        end

        private

        # Adds Kenna asset into memory (if one with the same `external_id` doesn't exist already)
        def add_asset(kenna_asset)
          return if (@assets || []).map { |asset| asset["external_id"] }.include?(kenna_asset["external_id"])

          create_kdi_asset(kenna_asset, false)
        end

        # Adds Kenna vulnerability into memory
        def add_vulnerability(external_asset_id, kenna_vulnerability)
          create_kdi_asset_vuln({ "external_id" => external_asset_id }, kenna_vulnerability, "external_id")
        end

        # Adds Kenna finding into memory
        def add_finding(external_asset_id, kenna_finding)
          create_kdi_asset_finding({ "external_id" => external_asset_id }, kenna_finding, "external_id")
        end

        # Adds Kenna definition into memory
        def add_definition(kenna_definition)
          create_kdi_vuln_def(kenna_definition)
        end

        # Gets current time in milliseconds
        def millis
          (Time.now.to_f * 1000).round
        end
      end
    end
  end
end
