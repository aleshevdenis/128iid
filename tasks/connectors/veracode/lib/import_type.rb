# frozen_string_literal: true

module Kenna
  module 128iid
    module Veracode
      class ImportType
        def self.named(type_string)
          case type_string.downcase
          when "findings"
            Findings.new
          else
            Vulns.new
          end
        end

        def extract_locator(issue, scan_type, app_name)
          scan_type.extract_locator(issue, app_name)
        end

        def extract_issue_attributes(_issue, _scan_type, _category_recommendations, _score_map)
          raise "Subclass responsibility"
        end

        def extract_definition(issue, scan_type, cwe_recommendations)
          scan_type.extract_definition(issue, cwe_recommendations)
        end
      end

      class Findings < ImportType
        def extract_issue_attributes(issue, scan_type, category_recommendations, score_map)
          scanner_score = issue["finding_details"].fetch("severity")
          { "scanner_identifier" => scan_type.scanner_identifier(issue),
            "vuln_def_name" => scan_type.vuln_def_name(issue),
            "scanner_type" => "veracode",
            "severity" => score_map[scanner_score.to_s].to_i / 10,
            "created_at" => issue["finding_status"].fetch("first_found_date"),
            "last_seen_at" => issue["finding_status"].fetch("last_seen_date"),
            "triage_state" => map_issue_status(issue),
            "additional_fields" => scan_type.finding_additional_fields(issue, category_recommendations) }.compact
        end

        def create_kdi_issue(task, asset, finding)
          task.create_kdi_asset_finding(asset, finding)
        end

        def map_issue_status(issue)
          case issue["finding_status"]["status"]
          when "CLOSED"
            # status = "closed"
            if issue["finding_status"]["resolution"] == "POTENTIAL_FALSE_POSITIVE"
              "false_positive"
            else
              "resolved"
            end
          else
            # status = "open"
            if issue["finding_status"]["new"]
              "new"
            else
              "in_progress"
            end
          end
        end
      end

      class Vulns < ImportType
        def extract_issue_attributes(issue, scan_type, category_recommendations, score_map)
          scanner_score = issue["finding_details"].fetch("severity")
          { "scanner_identifier" => scan_type.scanner_identifier(issue),
            "vuln_def_name" => scan_type.vuln_def_name(issue),
            "scanner_type" => "veracode",
            "scanner_score" => score_map[scanner_score.to_s].to_i / 10,
            "override_score" => score_map[scanner_score.to_s].to_i,
            "details" => scan_type.vuln_details(issue, category_recommendations),
            "created_at" => issue["finding_status"].fetch("first_found_date"),
            "last_seen_at" => issue["finding_status"].fetch("last_seen_date"),
            "status" => map_issue_status(issue) }.compact
        end

        def create_kdi_issue(task, asset, vuln)
          task.create_kdi_asset_vuln(asset, vuln)
        end

        def map_issue_status(issue)
          case issue["finding_status"]["status"]
          when "CLOSED"
            "closed"
          else
            "open"
          end
        end
      end
    end
  end
end
