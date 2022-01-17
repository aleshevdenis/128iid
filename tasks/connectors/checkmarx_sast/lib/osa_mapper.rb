# frozen_string_literal: true

module Kenna
  module 128iid
    module CheckmarxSast
      class OsaMapper
        SEVERITY_MAP = { "High" => 9, "Medium" => 6, "Low" => 3, "Information" => 0 }.freeze
        SCANNER_TYPE = "CheckmarxOsa"

        attr_reader :project, :issue

        def initialize(project, issue)
          @project = project
          @issue = issue
        end

        def extract_asset
          {
            "url" => issue.fetch("url"),
            "file" => (issue.fetch("sourceFileName") if issue.fetch("sourceFileName").present?),
            "application" => project.fetch("name")
          }.compact
        end

        def extract_finding
          {
            "scanner_identifier" => issue.fetch("id"),
            "scanner_type" => SCANNER_TYPE,
            "severity" => SEVERITY_MAP[issue["severity"]["name"]],
            "vuln_def_name" => vuln_def_name,
            "triage_state" => triage_state(issue["state"]["name"]),
            "additional_fields" => extract_additional_fields
          }.compact
        end

        def extract_additional_fields
          {
            "Issue ID" => issue["id"],
            "Project" => project["name"],
            "OSA Score" => issue["score"],
            "OSA Severity" => issue["severity"]["name"],
            "OSA State" => issue["state"]["name"],
            "Publish Date" => issue["publishDate"],
            "Description" => issue["description"],
            "Recommendation" => issue["recommendation"],
            "Library ID" => issue["libraryId"],
            "Fix URL" => issue["fixUrl"]
          }.compact
        end

        def extract_vuln_def
          cve = issue["cveName"] if issue["cveName"].match?(/CVE-.*/)
          {
            "scanner_type" => SCANNER_TYPE,
            "name" => vuln_def_name,
            "description" => issue["description"],
            "solution" => issue["recommendations"],
            "cve_identifiers" => cve
          }.compact
        end

        private

        def vuln_def_name
          issue["cveName"]
        end

        # OSA States are: "To Verify", "Not Exploitable", "Confirmed", "Urgent", "Propose Not Exploitable"
        # Kenna States are: "new", "in_progress", "triaged", "resolved", "false_positive", "risk_accepted", "duplicate", "not_a_security_issue".
        def triage_state(osa_state)
          case osa_state
          when "CONFIRMED"
            "risk_accepted"
          when "NOT_EXPLOITABLE", "PROPOSE_NOT_EXPLOITABLE"
            "not_a_security_issue"
          else
            "new"
          end
        end
      end
    end
  end
end
