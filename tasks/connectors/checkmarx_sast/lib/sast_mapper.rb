# frozen_string_literal: true

module Kenna
  module 128iid
    module CheckmarxSast
      class SastMapper
        SEVERITY_MAP = { "High" => 9, "Medium" => 6, "Low" => 3, "Information" => 0 }.freeze
        SCANNER_TYPE = "CheckmarxSast"

        attr_reader :report, :query, :issue

        def initialize(report, query, issue)
          @report = report
          @query = query
          @issue = issue
        end

        def extract_asset
          application = report.fetch("ProjectName")
          path = issue["Path"]
          if path.present?
            path_node = path.fetch("PathNode")
            filename = path_node_info(path_node, "FileName")
          end

          {
            "file" => filename,
            "application" => application
          }.compact
        end

        def extract_finding
          {
            "scanner_identifier" => issue["NodeId"],
            "scanner_type" => SCANNER_TYPE,
            "created_at" => (iso_date(issue["DetectionDate"]) if issue["DetectionDate"].present?),
            "severity" => SEVERITY_MAP[issue["Severity"]],
            "vuln_def_name" => vuln_def_name,
            "additional_fields" => extract_additional_fields
          }.compact
        end

        def extract_additional_fields
          path_node = issue.dig("Path", "PathNode")
          {
            "Team" => report.fetch("Team"),
            "group" => query.fetch("group"),
            "Language" => query.fetch("Language"),
            "DeepLink" => issue.fetch("DeepLink"),
            "Line" => path_node_info(path_node, "Line"),
            "Column" => path_node_info(path_node, "Column"),
            "NodeId" => path_node_info(path_node, "NodeId"),
            "Name" => path_node_info(path_node, "Name"),
            "Type" => path_node_info(path_node, "Type"),
            "Length" => path_node_info(path_node, "Length"),
            "Snippet" => snippet(path_node)
          }.compact
        end

        def extract_vuln_def
          {
            "scanner_type" => SCANNER_TYPE,
            "name" => vuln_def_name,
            "cwe_identifiers" => ("CWE-#{query['cweId']}" if query["cweId"].present?)
          }.compact
        end

        private

        def vuln_def_name
          query["name"].to_s
        end

        def snippet(path_node)
          snippet = path_node_info(path_node, "Snippet")
          snippet["Line"]["Code"].strip!
          snippet
        end

        def path_node_info(path_node, field)
          case path_node
          when Hash
            path_node.fetch(field)
          when Array
            path_node[0].fetch(field)
          end
        end

        def iso_date(date)
          DateTime.strptime(date, "%m/%d/%Y %k:%M:%S %p").iso8601
        end
      end
    end
  end
end
