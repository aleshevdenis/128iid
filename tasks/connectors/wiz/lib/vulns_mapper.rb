# frozen_string_literal: true

require_relative "mapper"
module Kenna
  module 128iid
    module Wiz
      class VulnsMapper < Mapper
        def name
          "Vuln"
        end

        def plural_name
          "Vulns"
        end

        def extract_asset(vuln)
          asset = {
            "external_id" => extract_external_id(vuln),
            "owner" => vuln["vulnerableAsset"]["subscriptionExternalId"],
            "image_id" => (vuln["vulnerableAsset"]["imageId"] if vuln["vulnerableAsset"]["imageId"].present?),
            "hostname" => extract_hostname(vuln),
            "os" => (vuln["vulnerableAsset"]["operatingSystem"] if vuln["vulnerableAsset"]["type"] == "VIRTUAL_MACHINE"),
            "ip_address" => ((vuln["vulnerableAsset"]["ipAddresses"] || []).first if vuln["vulnerableAsset"]["type"] == "VIRTUAL_MACHINE"),
            "tags" => extract_tags(vuln)
          }.compact
          asset["asset_type"] = "image" if asset["image_id"]
          asset
        end

        def extract_tags(vuln)
          tags = vuln["vulnerableAsset"]["tags"].map { |k, v| "#{k}:#{v}" }
          tags << "WizAssetType:#{vuln['vulnerableAsset']['type']}" if vuln["vulnerableAsset"]["type"].present?
          tags << "Region:#{vuln['vulnerableAsset']['region']}" if vuln["vulnerableAsset"]["region"].present?
          tags << "CloudPlatform:#{vuln['vulnerableAsset']['cloudPlatform']}" if vuln["vulnerableAsset"]["cloudPlatform"].present?
        end

        def extract_vuln(vuln)
          vuln = {
            "scanner_identifier" => vuln["id"],
            "scanner_type" => SCANNER_TYPE,
            "vuln_def_name" => extract_vuln_def_name(vuln),
            "scanner_score" => SEVERITY_MAP[vuln["vendorSeverity"].downcase],
            "created_at" => vuln["firstDetectedAt"],
            "last_seen_at" => vuln["lastDetectedAt"],
            "details" => extract_details(vuln)
          }
          vuln.compact
        end

        def extract_vuln_def_name(vuln)
          vuln["name"]
        end

        def extract_definition(vuln)
          cve = (vuln["name"] || "").scan(/CVE-\d*-\d*/).join(", ")
          {
            "name" => extract_vuln_def_name(vuln),
            "description" => vuln["CVEDescription"] || vuln["description"] || vuln["name"],
            "solution" => vuln["remediation"],
            "cve_identifiers" => (cve if cve.present?),
            "scanner_type" => SCANNER_TYPE
          }.compact
        end

        def extract_details(vuln)
          details = {
            "Vuln ID" => vuln["id"],
            "Cloud Provider URL" => vuln["vulnerableAsset"]["cloudProviderURL"],
            "Detailed File Path" => vuln["locationPath"],
            "Description" => vuln["description"],
            "Version" => vuln["version"],
            "Fixed Version" => vuln["fixedVersion"],
            "Score" => vuln["score"],
            "Exploitability Score" => vuln["exploitabilityScore"],
            "Impact Score" => vuln["impactScore"],
            "Link" => vuln["link"],
            "Projects" => vuln["projects"],
            "Vulnerable Asset" => vuln["vulnerableAsset"].except("tags", "cloudProviderURL")
          }.compact
          JSON.pretty_generate(details)
        end

        def extract_external_id(vuln)
          if vuln["vulnerableAsset"][@external_id_attr].present?
            vuln["vulnerableAsset"][@external_id_attr]
          else
            vuln["vulnerableAsset"]["id"]
          end
        end

        def extract_hostname(vuln)
          if vuln["vulnerableAsset"][@hostname_attr].present?
            vuln["vulnerableAsset"][@hostname_attr]
          else
            (vuln["vulnerableAsset"]["name"] if vuln["vulnerableAsset"]["type"] == "VIRTUAL_MACHINE")
          end
        end
      end
    end
  end
end
