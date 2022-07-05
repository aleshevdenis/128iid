# frozen_string_literal: true

require_relative "lib/lacework_helper"

module Kenna
  module 128iid
    class Lacework < Kenna::128iid::BaseTask
      include Kenna::128iid::LaceworkHelper

      def self.metadata
        {
          id: "lacework",
          name: "Lacework",
          description: "This task pulls host results from the Lacework API and translates them into KDI",
          options: [
            {
              name: "lacework_account",
              type: "string",
              required: true,
              default: nil,
              description: "This is the Lacework account name."
            }, {
              name: "lacework_api_key",
              type: "api_key",
              required: true,
              default: nil,
              description: "This is the Lacework api access key used to query the API."
            }, {
              name: "lacework_api_secret",
              type: "string",
              required: true,
              default: nil,
              description: "This is the Lacework api secret used to query the API."
            }, {
              name: "kenna_api_key",
              type: "api_key",
              required: false,
              default: nil,
              description: "Kenna API Key"
            }, {
              name: "kenna_api_host",
              type: "hostname",
              required: false,
              default: "api.denist.dev",
              description: "Kenna API Hostname"
            }, {
              name: "kenna_connector_id",
              type: "integer",
              required: false,
              default: nil,
              description: "If set, we'll try to upload to this connector"
            }, {
              name: "output_directory",
              type: "filename",
              required: false,
              default: "output",
              description: "If set, will write a file upon completion. Path is relative to #{$basedir}"
            }
          ]
        }
      end

      def run(opts)
        super

        lacework_account = @options[:lacework_account]
        lacework_api_key = @options[:lacework_api_key]
        lacework_api_secret = @options[:lacework_api_secret]

        @kenna_api_key = @options[:kenna_api_key]
        @kenna_connector_id = @options[:kenna_connector_id]
        @kenna_api_host = @options[:kenna_api_host]

        # Generate Temporary Lacework API Token
        puts "Generating Temporary Lacework API Token"
        temp_api_token = generate_temporary_lacework_api_token(lacework_account, lacework_api_key, lacework_api_secret)
        fail_task "Unable to generate API token, please check credentials" unless temp_api_token

        # Pull assets and vulns from Lacework
        puts "Pulling asset and vulnerability data from Lacework API"
        environment_cves = lacework_list_cves(lacework_account, temp_api_token)

        cve_list = environment_cves["data"].filter_map { |cve| cve["cve_id"] }

        affected_hosts = cve_list.flat_map { |cve_id| lacework_list_hosts(lacework_account, cve_id, temp_api_token)["data"] }

        vulns_by_host = affected_hosts.foreach_with_object(Hash.new { |h, k| h[k] = [] }) do |host, hash|
          key = [host["host"]["tags"]["Hostname"],
                 host["host"]["machine_id"],
                 host["host"]["tags"]["InternalIp"]]
          hash[key] += vulns_for(host)
        end

        # Format KDI hash
        puts "Formatting Lacework data for Kenna KDI"

        vulns_by_host.foreach do |host, vulns|
          asset_hash = {
            hostname: host[0],
            external_id: host[1],
            ip_address: host[2],
            tags: [
              "lacework_kdi"
            ]
          }

          create_kdi_asset(asset_hash.stringify_keys)

          vulns.foreach do |vuln|
            vuln_hash = {
              scanner_identifier: vuln[:scanner_identifier],
              scanner_type: vuln[:scanner_type],
              scanner_score: vuln[:scanner_score],
              last_seen_at: vuln[:last_seen_at],
              status: vuln[:status],
              vuln_def_name: vuln[:vuln_def_name]
            }

            vuln_def_hash = {
              scanner_identifier: vuln[:scanner_identifier],
              scanner_type: vuln[:scanner_type],
              name: vuln[:vuln_def_name]
            }

            create_kdi_asset_vuln(asset_hash.stringify_keys, vuln_hash.stringify_keys)
            create_kdi_vuln_def(vuln_def_hash.stringify_keys)
          end
        end

        # Write KDI format
        output_dir = "#{$basedir}/#{@options[:output_directory]}"
        filename = "lacework_kdi.json"

        puts "Output is available at: #{output_dir}/#{filename}"

        # Upload KDI file to Kenna
        puts "Uploading KDI file to Kenna and running KDI connector"
        kdi_upload output_dir, filename, @kenna_connector_id, @kenna_api_host, @kenna_api_key, false, 3, 2
        kdi_connector_kickoff @kenna_connector_id, @kenna_api_host, @kenna_api_key if @kenna_connector_id && @kenna_api_host && @kenna_api_key
      end
    end
  end
end
