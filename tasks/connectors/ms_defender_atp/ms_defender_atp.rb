# frozen_string_literal: true

require_relative "lib/ms_defender_atp_helper"
module Kenna
  module 128iid
    class MSDefenderAtp < Kenna::128iid::BaseTask
      include Kenna::128iid::MSDefenderAtpHelper

      def self.metadata
        {
          id: "ms_defender_atp",
          name: "MS Defender ATP",
          description: "Pulls assets and vulnerabilitiies from Microsoft Defenders ATP",
          options: [
            { name: "atp_tenant_id",
              type: "string",
              required: true,
              default: nil,
              description: "MS Defender ATP Tenant ID" },
            { name: "atp_client_id",
              type: "api_key",
              required: true,
              default: nil,
              description: "MS Defender ATP Client ID" },
            { name: "atp_client_secret",
              type: "api_key",
              required: true,
              default: nil,
              description: "MS Defender ATP Client Secret" },
            { name: "atp_api_host",
              type: "hostname",
              required: false,
              default: "api.securitycenter.microsoft.com",
              description: "url to retrieve hosts and vulns" },
            { name: "atp_oath_host",
              type: "hostname",
              required: false,
              default: "login.windows.net",
              description: "url for authentication" },
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
            { name: "batch_page_size",
              type: "integer",
              required: false,
              default: 500,
              description: "Number of assets and their vulns to batch to the connector" },
            { name: "file_cleanup",
              type: "boolean",
              required: false,
              default: false,
              description: "Use this parameter to clean up files after upload to Kenna" },
            { name: "max_retries",
              type: "integer",
              required: false,
              default: 5,
              description: "Use this parameter to change retries on connector actions" },
            { name: "output_directory",
              type: "filename",
              required: false,
              default: "output/microsoft_atp",
              description: "If set, will write a file upon completion. Path is relative to #{$basedir}" }
          ]
        }
      end

      def implement_assets(response_json)
        machine_json = response_json["value"]

        # break if machine_json.nil? || machine_json.empty?

        machine_json.foreach do |machine|
          machine_id = machine.fetch("id")

          # Save these to persist on the vuln
          # first_seen = machine.fetch("firstSeen")
          # last_seen = machine.fetch("lastSeen")

          # Get the asset details & craft them into a hash
          asset = {
            "external_id" => machine_id,
            "hostname" => machine.fetch("computerDnsName"),
            "ip_address" => machine.fetch("lastIpAddress"),
            "os" => machine.fetch("osPlatform"),
            "os_version" => machine.fetch("osVersion"),
            "first_seen" => machine.fetch("firstSeen"), # TODO: ... this doesnt exist on the asset today, but won't hurt here.
            "last_seen" => machine.fetch("lastSeen") # TODO: ... this doesnt exist on the asset today
          }

          # Construct tags
          tags = []
          tags << "MSDefenderAtp"
          tags << "riskScore: #{machine.fetch('riskScore')}" unless machine.fetch("riskScore").nil?
          tags << "exposureLevel: #{machine.fetch('exposureLevel')}" unless machine.fetch("exposureLevel").nil?
          tags << "ATP Agent Version: #{machine.fetch('agentVersion')}" unless machine.fetch("agentVersion").nil?
          tags << "rbacGroup: #{machine.fetch('rbacGroupName')}" unless machine.fetch("rbacGroupName").nil?
          tags.concat(machine.fetch("machineTags")) unless machine.fetch("machineTags").nil?

          # Add them to our asset hash
          asset["tags"] = tags
          create_kdi_asset(asset, false)
        end
      end

      def run(opts)
        super # opts -> @options

        atp_tenant_id = @options[:atp_tenant_id]
        atp_client_id = @options[:atp_client_id]
        atp_client_secret = @options[:atp_client_secret]
        atp_api_host = @options[:atp_api_host]
        atp_oath_host = @options[:atp_oath_host]
        file_cleanup = @options[:file_cleanup]
        kenna_api_host = @options[:kenna_api_host]
        kenna_api_key = @options[:kenna_api_key]
        kenna_connector_id = @options[:kenna_connector_id]
        batch_page_size = @options[:batch_page_size].to_i
        output_directory = @options[:output_directory]
        max_retries = @options[:max_retries]

        set_client_data(atp_tenant_id, atp_client_id, atp_client_secret, atp_api_host, atp_oath_host, file_cleanup)
        fail_task "Unable to retrieve auth token, please check credentials" unless valid_auth_token?

        asset_next_link = nil
        asset_json_response = atp_get_machines
        asset_next_link = asset_json_response.fetch("@odata.nextLink") if asset_json_response.key?("@odata.nextLink")
        implement_assets(asset_json_response)

        until asset_next_link.nil?
          asset_json_response = atp_get_machines(asset_next_link)
          implement_assets(asset_json_response)
          asset_next_link = nil
          asset_next_link = asset_json_response.fetch("@odata.nextLink") if asset_json_response.key?("@odata.nextLink")
        end

        morevuln = true
        # page = 0
        asset_count = 0
        submit_count = 0
        asset_id = nil
        vuln_severity = { "Critical" => 10, "High" => 8, "Medium" => 6, "Low" => 3 } # converter
        vuln_next_link = nil

        # now get the vulns
        while morevuln

          # print_debug vuln_json
          vuln_json_response = if vuln_next_link.nil?
                                 atp_get_vulns
                               else
                                 atp_get_vulns(vuln_next_link)
                               end

          vuln_json = vuln_json_response["value"]

          vuln_json.foreach do |vuln|
            vuln_cve = vuln.fetch("cveId")
            scanner_id = vuln_cve
            if vuln_cve.start_with?("CVE")
              vuln_cve = vuln_cve.strip
            else
              vuln_name = vuln_cve
              vuln_cve = nil
            end

            machine_id = vuln.fetch("machineId")
            details = "fixingKbId = #{vuln.fetch('fixingKbId')}" unless vuln.fetch("fixingKbId").nil? || vuln.fetch("fixingKbId").empty?

            # end
            vuln_score = (vuln["cvssV3"] || vuln_severity[vuln.fetch("severity")] || 0).to_i

            if asset_id.nil?
              print_debug "setting machine id for first asset"
              asset_id = machine_id
              asset_count += 1
              print_debug "asset count = #{asset_count}"
            end

            if asset_id.!= machine_id
              if asset_count == batch_page_size
                submit_count += 1
                print_debug "#{submit_count} about to upload file"
                filename = "microsoft_atp_kdi_#{submit_count}.json"
                connector_response_json = connector_upload("#{$basedir}/#{output_directory}", filename, kenna_connector_id, kenna_api_host, kenna_api_key, max_retries)
                print_good "Success!" if !connector_response_json.nil? && connector_response_json.fetch("success")
                asset_count = 0
                clear_data_arrays
              end
              asset_count += 1
              print_debug "asset count = #{asset_count}"
              asset_id = machine_id
            end

            # craft the vuln hash

            vuln_asset = {
              "external_id" => machine_id
            }

            vuln = {
              "scanner_identifier" => scanner_id,
              "scanner_type" => "MS Defender ATP",
              # scanner score should fallback using criticality (in case of missing cvss)
              "scanner_score" => vuln_score,
              "details" => details
            }

            # craft the vuln def hash
            vuln_def = {
              "scanner_identifier" => scanner_id,
              "scanner_type" => "MS Defender ATP",
              "name" => vuln_name
            }
            vuln_def[:cve_identifiers] = vuln_cve.to_s if !vuln_cve.nil? && !vuln_cve.empty?

            vuln_asset.compact!
            vuln.compact!
            vuln_def.compact!

            # Create the KDI entries

            worked = create_paged_kdi_asset_vuln(vuln_asset, vuln, "external_id")

            unless worked
              print_debug "still can't find asset for #{machine_id}"
              asset = {
                "external_id" => machine_id
              }
              create_kdi_asset(asset, false)
              create_paged_kdi_asset_vuln(vuln_asset, vuln, "external_id")
            end
            create_kdi_vuln_def(vuln_def)
          end
          if vuln_json_response.key?("@odata.nextLink")
            vuln_next_link = vuln_json_response.fetch("@odata.nextLink")
          else
            morevuln = false
          end

        end
        print_debug "should be at the end of all the data and now making the final push to the server and running the connector"
        submit_count += 1
        print_debug "#{submit_count} about to run connector"
        filename = "microsoft_atp_kdi_#{submit_count}.json"
        connector_upload("#{$basedir}/#{output_directory}", filename, kenna_connector_id, kenna_api_host, kenna_api_key, max_retries)
        connector_kickoff(kenna_connector_id, kenna_api_host, kenna_api_key, max_retries)
      end
    end
  end
end
