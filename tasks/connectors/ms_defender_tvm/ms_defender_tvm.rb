# frozen_string_literal: true

require_relative "lib/ms_defender_tvm_helper"
module Kenna
  module 128iid
    class MSDefenderTvm < Kenna::128iid::BaseTask
      include Kenna::128iid::MSDefenderTvmHelper

      def self.metadata
        {
          id: "ms_defender_tvm",
          name: "MS Defender TVM",
          description: "Pulls assets and vulnerabilitiies from Microsoft Defenders TVM",
          options: [
            { name: "tvm_tenant_id",
              type: "string",
              required: true,
              default: nil,
              description: "MS Defender TVM Tenant ID" },
            { name: "tvm_client_id",
              type: "api_key",
              required: true,
              default: nil,
              description: "MS Defender TVM Client ID" },
            { name: "tvm_client_secret",
              type: "api_key",
              required: true,
              default: nil,
              description: "MS Defender TVM Client Secret" },
            { name: "tvm_api_host",
              type: "hostname",
              required: false,
              default: "api.securitycenter.microsoft.com",
              description: "url to retrieve hosts and vulns" },
            { name: "tvm_oath_host",
              type: "hostname",
              required: false,
              default: "login.windows.net",
              description: "url for authentication" },
            { name: "tvm_page_size",
              type: "integer",
              required: false,
              default: 10_000,
              description: "url to retrieve hosts and vulns" },
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
              default: "output/microsoft_tvm",
              description: "If set, will write a file upon completion. Path is relative to #{$basedir}" }
          ]
        }
      end

      def run(opts)
        super # opts -> @options

        tvm_tenant_id = @options[:tvm_tenant_id]
        tvm_client_id = @options[:tvm_client_id]
        tvm_client_secret = @options[:tvm_client_secret]
        tvm_api_host = @options[:tvm_api_host]
        tvm_oath_host = @options[:tvm_oath_host]
        tvm_page_size = @options[:tvm_page_size]
        # file_cleanup = @options[:file_cleanup]
        @kenna_api_host = @options[:kenna_api_host]
        @kenna_api_key = @options[:kenna_api_key]
        @kenna_connector_id = @options[:kenna_connector_id]
        batch_page_size = @options[:batch_page_size].to_i
        output_directory = @options[:output_directory]
        @max_retries = @options[:max_retries]

        set_client_data(tvm_tenant_id, tvm_client_id, tvm_client_secret, tvm_api_host, tvm_oath_host, tvm_page_size)
        fail_task "Unable to retrieve auth token, please check credentials" unless valid_auth_token?

        morevuln = true
        asset_count = 0
        submit_count = 0
        asset_id = nil
        vuln_severity = { "Critical" => 10, "High" => 8, "Medium" => 6, "Low" => 3 } # converter
        vuln_next_link = nil

        # now get the vulns
        while morevuln

          # print_debug vuln_json
          vuln_json_response = if vuln_next_link.nil?
                                 tvm_get_vulns
                               else
                                 tvm_get_vulns(vuln_next_link)
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

            machine_id = vuln.fetch("deviceId")
            fqdn = vuln.fetch("deviceName")

            # Get the asset details & craft them into a hash
            asset = {
              "external_id" => machine_id,
              "fqdn" => fqdn,
              "hostname" => fqdn.split(".")[0],
              "os" => vuln.fetch("osPlatform"),
              "os_version" => vuln.fetch("osVersion"),
              "first_seen" => vuln.fetch("firstSeenTimestamp"),
              "last_seen" => vuln.fetch("lastSeenTimestamp")
            }

            # Construct tags
            tags = []
            tags << "MSDefenderTvm"
            tags << "rbacGroup: #{vuln.fetch('rbacGroupName')}" unless vuln.fetch("rbacGroupName").nil?

            # Add them to our asset hash
            asset["tags"] = tags
            vuln_score = (vuln_severity[vuln.fetch("vulnerabilitySeverityLevel")] || 0).to_i

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
                filename = "microsoft_tvm_kdi_#{submit_count}.json"
                kdi_upload("#{$basedir}/#{output_directory}", filename, @kenna_connector_id, @kenna_api_host, @kenna_api_key, false, 3)
                asset_count = 0
              end
              asset_count += 1
              print_debug "asset count = #{asset_count}"
              asset_id = machine_id
            end

            software_vendor = vuln&.fetch("softwareVendor")
            software_name = vuln.fetch("softwareName") if vuln.key?("softwareName")
            software_version = vuln.dig(:softwareVersion)
            vulnerability_severity_level = vuln.fetch("vulnerabilitySeverityLevel") if vuln.key?("vulnerabilitySeverityLevel")
            recommended_security_update = vuln.fetch("recommendedSecurityUpdate") if vuln.key?("recommendedSecurityUpdate")
            recommended_security_update_id = vuln.fetch("recommendedSecurityUpdateId") if vuln.key?("recommendedSecurityUpdateId")
            recommended_security_update_url = vuln.fetch("recommendedSecurityUpdateUrl") if vuln.key?("recommendedSecurityUpdateUrl")
            disk_paths = vuln.fetch("diskPaths") if vuln.key?("diskPaths")
            registry_paths = vuln.fetch("registryPaths") if vuln.key?("registryPaths")
            end_of_support_status = vuln.fetch("endOfSupportStatus") if vuln.key?("endOfSupportStatus")
            end_of_support_date = vuln.fetch("endOfSupportDate") if vuln.key?("endOfSupportDate")
            exploitability_level = vuln.fetch("exploitabilityLevel") if vuln.key?("exploitabilityLevel")
            recommendation_reference = vuln.fetch("recommendationReference") if vuln.key?("recommendationReference")

            details = {
              "softwareVendor" => software_vendor,
              "softwareName" => software_name,
              "softwareVersion" => software_version,
              "vulnerabilitySeverityLevel" => vulnerability_severity_level,
              "recommendedSecurityUpdate" => recommended_security_update,
              "recommendedSecurityUpdateId" => recommended_security_update_id,
              "recommendedSecurityUpdateUrl" => recommended_security_update_url,
              "diskPaths" => disk_paths,
              "registryPaths" => registry_paths,
              "endOfSupportStatus" => end_of_support_status,
              "endOfSupportDate" => end_of_support_date,
              "exploitabilityLevel" => exploitability_level,
              "recommendationReference" => recommendation_reference
            }

            details.compact!

            vuln_object = {
              "scanner_identifier" => scanner_id,
              "scanner_type" => "MS Defender TVM",
              # scanner score should fallback using criticality (in case of missing cvss)
              "scanner_score" => vuln_score,
              "details" => JSON.pretty_generate(details)
            }

            # craft the vuln def hash
            vuln_def = {
              "scanner_identifier" => scanner_id,
              "scanner_type" => "MS Defender TVM",
              "name" => vuln_name
            }
            vuln_def[:cve_identifiers] = vuln_cve.to_s if !vuln_cve.nil? && !vuln_cve.empty?

            asset.compact!
            vuln_object.compact!
            vuln_def.compact!
            create_kdi_asset_vuln(asset, vuln_object)
            create_kdi_vuln_def(vuln_def)
          end
          vuln_next_link = nil
          vuln_next_link = vuln_json_response.fetch("@odata.nextLink") if vuln_json_response.key?("@odata.nextLink")
          morevuln = false if vuln_next_link.nil?

        end
        print_debug "should be at the end of all the data and now making the final push to the server and running the connector"
        submit_count += 1
        print_debug "#{submit_count} about to run connector"
        filename = "microsoft_tvm_kdi_#{submit_count}.json"
        kdi_upload("#{$basedir}/#{output_directory}", filename, @kenna_connector_id, @kenna_api_host, @kenna_api_key, false, 3)
        kdi_connector_kickoff(@kenna_connector_id, @kenna_api_host, @kenna_api_key)
      end
    end
  end
end
