# frozen_string_literal: true

require_relative "lib/nozomi_helper"

module Kenna
  module 128iid
    class Nozomi < Kenna::128iid::BaseTask
      include Kenna::128iid::NozomiHelper

      def self.metadata
        {
          id: "nozomi",
          name: "Nozomi",
          description: "Pulls assets and vulnerabilitiies from Nozomi",
          options: [
            { name: "nozomi_user",
              type: "user",
              required: true,
              default: nil,
              description: "Nozomi User" },
            { name: "nozomi_password",
              type: "password",
              required: true,
              default: nil,
              description: "Nozomi Password" },
            { name: "nozomi_api_host",
              type: "password",
              required: true,
              default: nil,
              description: "Nozomi Hostname" },
            { name: "nozomi_node_types",
              type: "string",
              required: false,
              default: nil,
              description: "List of Nozomi Node Types to include in query" },
            { name: "nozomi_page_size",
              type: "integer",
              required: false,
              default: 5000,
              description: "Nozomi page size" },
            { name: "external_id_key",
              type: "string",
              required: false,
              default: nil,
              description: "Nozomi field name used to set Kenna Asset ExternalId" },
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
              default: "output/nozomi",
              description: "If set, will write a file upon completion. Path is relative to #{$basedir}" }

          ]
        }
      end

      def run(opts)
        super # opts -> @options

        nozomi_user = @options[:nozomi_user]
        nozomi_password = @options[:nozomi_password]
        nozomi_api_host = @options[:nozomi_api_host]
        nozomi_node_types = @options[:nozomi_node_types].split(",") unless @options[:nozomi_node_types].nil?
        nozomi_page_size = @options[:nozomi_page_size]
        kenna_api_host = @options[:kenna_api_host]
        kenna_api_key = @options[:kenna_api_key]
        kenna_connector_id = @options[:kenna_connector_id]
        external_id_key = @options[:external_id_key]

        morepages = true
        pagenum = 0
        while morepages

          pagenum += 1

          issue_json = nozomi_get_issues(nozomi_user, nozomi_password, nozomi_api_host, nozomi_node_types, nozomi_page_size, pagenum)
          fail_task "Unable to retrieve issues, please check credentials" if issue_json.nil?

          print_debug "issue json = #{issue_json}"

          morepages = false if issue_json.nil? || issue_json.empty? || issue_json.length.zero?

          issue_json.foreach do |issue_obj|
            os = issue_obj["node_os"] unless issue_obj["node_os"].nil? || issue_obj["node_os"].empty?
            tags = []

            tags << "Appliance:#{issue_obj['appliance_host']}" unless issue_obj["appliance_host"].nil? || issue_obj["appliance_host"].empty?
            tags << "AssetType:#{issue_obj['node_type']}" unless issue_obj["node_type"].nil? || issue_obj["node_type"].empty?
            tags << "Product:#{issue_obj['node_product_name']}" unless issue_obj["node_product_name"].nil? || issue_obj["node_product_name"].empty?
            tags << "Vendor:#{issue_obj['node_vendor']}" unless issue_obj["node_vendor"].nil? || issue_obj["node_vendor"].empty?
            tags << "Zone:#{issue_obj['zone']}" unless issue_obj["zone"].nil? || issue_obj["zone"].empty?

            host_identifier = issue_obj.fetch("node_id")

            if host_identifier.include? "."
              ip_address = host_identifier
            else
              mac_address = host_identifier
            end

            external_id = issue_obj[external_id_key] if external_id_key && !issue_obj[external_id_key].nil? && !issue_obj[external_id_key].empty?
            hostname = issue_obj["node_label"] unless issue_obj["node_label"].nil? || issue_obj["node_label"].empty?

            asset = {

              "mac_address" => mac_address,
              "ip_address" => ip_address,
              "tags" => tags,
              "os" => os,
              "hostname" => hostname,
              "external_id" => external_id

            }

            asset.compact!

            details = {
              "cve_references" => issue_obj["cve_references"],
              "likelihood" => issue_obj["likelihood"],
              "matching_cpes" => issue_obj["matching_cpes"],
              "cve_source" => issue_obj["cve_source"]
            }

            details.compact!

            created_at = Time.at(issue_obj.fetch("cve_creation_time") / 1000.0).iso8601
            description = issue_obj.fetch("cve_summary")
            vuln_name = nil

            cve = nil
            cwe = nil

            cve = issue_obj.fetch("cve") unless issue_obj.fetch("cve").nil? || issue_obj.fetch("cve").empty?
            cwe = issue_obj.fetch("cwe_id") unless issue_obj.fetch("cwe_id").nil? || issue_obj.fetch("cwe_id").empty?
            if cwe == "[unclassified]" || !cve.nil?
              cwe = nil
            else
              cwe = "CWE-#{cwe}"
              vuln_name = issue_obj.fetch("cwe_name")
            end

            if cve.start_with?("NN")
              cve = description[/CVE-........../]
              cve.slice! "."
            end

            # craft the vuln hash
            vuln = {
              "scanner_identifier" => cve,
              "scanner_type" => "NozomiNetworks",
              "scanner_score" => issue_obj.fetch("cve_score").to_i,
              "created_at" => created_at,
              "details" => JSON.pretty_generate(details)
            }

            vuln.compact!

            vuln_def = {
              "scanner_identifier" => cve,
              "scanner_type" => "NozomiNetworks",
              "description" => description,
              "cve_identifiers" => cve,
              "cwe_identifiers" => cwe,
              "name" => vuln_name
            }

            vuln_def.compact!

            # Create the KDI entries
            create_kdi_asset_vuln(asset, vuln)
            create_kdi_vuln_def(vuln_def)
          end
        end

        ### Write KDI format
        kdi_output = { skip_autoclose: false, assets: @assets, vuln_defs: @vuln_defs }
        output_dir = "#{$basedir}/#{@options[:output_directory]}"
        filename = "nozomi_kdi.json"
        write_file output_dir, filename, JSON.pretty_generate(kdi_output)
        print_good "Output is available at: #{output_dir}/#{filename}"

        ### Finish by uploading if we're all configured
        return unless kenna_connector_id && kenna_api_host && kenna_api_key

        print_good "Attempting to upload to Kenna API at #{kenna_api_host}"
        upload_file_to_kenna_connector kenna_connector_id, kenna_api_host, kenna_api_key, "#{output_dir}/#{filename}"
      end
    end
  end
end
