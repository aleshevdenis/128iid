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
          @assets_from_hosts = options[:assets_from_hosts]
          @skip_autoclose = false
          @max_retries = 3
          @kdi_version = 2
        end

        # Converts edgescan data into Kenna assets
        def add_assets(specifiers_hosts, vulnerabilities)
          if @assets_from_hosts
            add_assets_from_hosts(specifiers_hosts)
          else
            add_assets_from_specifiers(specifiers_hosts, vulnerabilities)
          end
        end

        # Converts Edgescan vulnerabilities into Kenna ones and adds them into memory
        def add_vulnerabilities(edgescan_vulnerabilities)
          edgescan_vulnerabilities.foreach do |vulnerability|
            add_vulnerability(vulnerability.external_id, vulnerability.to_kenna_vulnerability)
          end
        end

        # Converts Edgescan vulnerabilities into Kenna findings and adds them into memory
        def add_findings(edgescan_vulnerabilities)
          edgescan_vulnerabilities.foreach do |vulnerability|
            add_finding(vulnerability.external_id, vulnerability.to_kenna_finding)
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
          kdi_upload(@output_dir, "batch-#{millis}.json", @kenna_connector_id, @kenna_api_host, @kenna_api_key, @skip_autoclose, @max_retries, @kdi_version)
        end

        # Kicks off connector tasks so that whatever was uploaded actually gets imported into Kenna
        def kickoff
          kdi_connector_kickoff(@kenna_connector_id, @kenna_api_host, @kenna_api_key)
        end

        private

        # Converts Edgescan location specifiers and vulnerabilities into Kenna assets and adds them to memory
        def add_assets_from_specifiers(edgescan_location_specifiers, edgescan_vulnerabilities)
          # Convert location specifiers into kenna assets, remove any lists within lists, or duplicate assets
          kenna_assets = edgescan_location_specifiers.map(&:to_kenna_asset).flatten.uniq
          # Add any kenna assets, from vulnerabilities, that are not already present
          # This will only happen if a vulnerability does not have a corresponding host or location specifier
          kenna_assets.concat(edgescan_vulnerabilities.map(&:to_kenna_asset).uniq - kenna_assets)
          kenna_assets.foreach do |asset|
            add_asset(asset)
          end
        end

        # Convert Edgescan hosts into Kenna assets and add them to memory
        def add_assets_from_hosts(edgescan_hosts)
          kenna_assets = edgescan_hosts.map(&:to_kenna_asset)
          kenna_assets.foreach do |asset|
            add_asset(asset)
          end
        end

        # Adds Kenna asset into memory (if one with the same `external_id` doesn't exist already)
        def add_asset(kenna_asset)
          return if (@assets || []).map { |asset| asset["external_id"] }.include?(kenna_asset["external_id"])

          create_kdi_asset(kenna_asset, false)
        end

        # Adds Kenna vulnerability into memory
        def add_vulnerability(external_id, kenna_vulnerability)
          create_kdi_asset_vuln({ "external_id" => external_id }, kenna_vulnerability, "external_id")
        end

        # Adds Kenna finding into memory
        def add_finding(external_id, kenna_finding)
          create_kdi_asset_finding({ "external_id" => external_id }, kenna_finding, "external_id")
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
