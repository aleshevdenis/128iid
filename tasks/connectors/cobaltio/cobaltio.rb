# frozen_string_literal: true

require_relative "lib/cobaltio_helper"

module Kenna
  module 128iid
    class Cobaltio < Kenna::128iid::BaseTask
      include Kenna::128iid::CobaltioHelper

      SCANNER = "Cobalt.io"

      def self.metadata
        {
          id: "cobaltio",
          name: "Cobalt.io",
          description: "Pulls findings from Cobalt.io",
          options: [
            { name: "cobalt_api_token",
              type: "api_key",
              required: true,
              default: nil,
              description: "Cobalt.io API token" },
            { name: "cobalt_org_token",
              type: "api_key",
              required: true,
              default: nil,
              description: "Cobalt.io org token" },
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
              required: true,
              default: nil,
              description: "If set, we'll try to upload to this connector" },
            { name: "kenna_appsec_module",
              type: "boolean",
              required: false,
              default: true,
              description: "Controls whether to use the newer Kenna AppSec module, set to false if you want to use the VM module (and group by CWE)" },
            { name: "output_directory",
              type: "filename",
              required: false,
              default: "output/cobaltio",
              description: "If set, will write a file upon completion. Path is relative to #{$basedir}" }
          ]
        }
      end

      def run(opts)
        super # opts -> @options

        cobalt_api_token = @options[:cobalt_api_token]
        cobalt_org_token = @options[:cobalt_org_token]

        @kenna_api_host = @options[:kenna_api_host]
        @kenna_api_key = @options[:kenna_api_key]
        @kenna_connector_id = @options[:kenna_connector_id]
        @kenna_appsec_module = @options[:kenna_appsec_module]

        # output_directory = @options[:output_directory]

        findings_json = cobalt_get_findings(cobalt_api_token, cobalt_org_token)
        print_debug "findings json = #{findings_json}"
        fail_task "Unable to retrieve findings, please check credentials" if findings_json.nil?

        severity_map = { "high" => 7, "medium" => 5, "low" => 3 } # converter
        state_map = { "need_fix" => "new", "wont_fix" => "risk_accepted", "valid_fix" => "resolved", "check_fix" => "in_progress", "carried_over" => "new" }
        status_map = { "need_fix" => "open", "wont_fix" => "closed", "valid_fix" => "closed", "check_fix" => "open", "carried_over" => "open" }
        findings_json.foreach do |finding_obj|
          next if cobalt_exclude_finding(finding_obj)

          resource = finding_obj["resource"]
          links = finding_obj["links"]
          log = resource["log"]

          asset_id = resource["asset_id"]
          cobalt_asset = cobalt_get_asset(cobalt_api_token, cobalt_org_token, asset_id)
          application = cobalt_asset["resource"]["title"] if cobalt_asset

          asset = {
            "external_id" => asset_id,
            "application" => application,
          }

          vuln_def_name = resource["title"]
          description = resource["description"]
          solution = resource.fetch("suggested_fix") if resource.key?("suggested_fix")

          vuln_def = {
            "scanner_type" => SCANNER,
            "name" => vuln_def_name,
            "description" => description,
            "solution" => solution,
          }
          vuln_def.compact!
          create_kdi_vuln_def(vuln_def)

          scanner_identifier = resource["id"]
          created_at = cobalt_get_created(log)
          last_seen_at = created_at
          severity = severity_map.fetch(resource.fetch("severity"))
          triage_state = state_map.fetch(resource["state"])
          vuln_status = status_map.fetch(resource["state"])

          if @kenna_appsec_module == true
            impact = resource["impact"]
            likelihood = resource["likelihood"]
            proof_of_concept = resource.fetch("proof_of_concept") if resource.key?("proof_of_concept")
            cobalt_state = resource["state"]
            cobalt_url = links["ui"]["url"]

            additional_fields = {
              "impact" => impact,
              "likelihood" => likelihood,
              "proof_of_concept" => proof_of_concept,
              "cobalt_state" => cobalt_state,
              "cobalt_url" => cobalt_url,
            }
            additional_fields.compact!

            finding = {
              "scanner_type" => SCANNER,
              "scanner_identifier" => scanner_identifier,
              "created_at" => created_at,
              "last_seen_at" => last_seen_at,
              "severity" => severity,
              "vuln_def_name" => vuln_def_name,
              "triage_state" => triage_state,
              "additional_fields" => additional_fields,
            }
            finding.compact!

            create_kdi_asset_finding(asset, finding)
          else
            vuln = {
              "scanner_type" => SCANNER,
              "scanner_identifier" => scanner_identifier,
              "scanner_score" => severity,
              "created_at" => created_at,
              "last_seen_at" => last_seen_at,
              "status" => vuln_status,
              "vuln_def_name" => vuln_def_name,
            }
            vuln.compact!

            create_kdi_asset_vuln(asset, vuln)
          end
        end

        ### Write KDI format
        output_dir = "#{$basedir}/#{@options[:output_directory]}"
        filename = "cobaltio_kdi.json"
        kdi_upload output_dir, filename, @kenna_connector_id, @kenna_api_host, @kenna_api_key, false, 3, 2
        kdi_connector_kickoff @kenna_connector_id, @kenna_api_host, @kenna_api_key if @kenna_connector_id && @kenna_api_host && @kenna_api_key
      end
    end
  end
end
