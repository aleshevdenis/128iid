# frozen_string_literal: true

module Kenna
  module 128iid
    module Veracode
      class ScanType
        def self.named(type_string)
          case type_string
          when "STATIC"
            Static.new
          when "MANUAL"
            Manual.new
          when "DYNAMIC"
            Dynamic.new
          when "SCA"
            SCA.new
          else
            raise "Invalid Type: #{type_string}"
          end
        end

        def extract_locator(_issue, _app_name)
          raise "Subclass responsibility"
        end

        def scanner_identifier(issue)
          issue.fetch("issue_id")
        end

        def vuln_def_name(issue)
          cwe(issue)
        end

        def vuln_details(issue, category_recommendations)
          finding_rec = category_recommendations.find { |r| r["id"] == issue["finding_details"]["finding_category"].fetch("id") }["recommendation"]
          "Recommendation:\n\n#{finding_rec}\n\n===============\n\n#{JSON.pretty_generate(extract_additional_information(issue))}"
        end

        def finding_additional_fields(issue, category_recommendations)
          finding_rec = category_recommendations.find { |r| r["id"] == issue["finding_details"]["finding_category"].fetch("id") }["recommendation"]
          extract_additional_information(issue, finding_rec)
        end

        def extract_definition(issue, cwe_recommendations)
          cwe = cwe(issue)
          cwe_rec = cwe_recommendations.find { |r| r["id"] == issue["finding_details"]["cwe"].fetch("id") }["recommendation"]
          cwe_rec = "No CWE recommendation provided by Veracode. See category recommendation on Details tab." if cwe_rec == ""
          { "name" => cwe,
            "scanner_type" => "veracode",
            "cwe_identifiers" => cwe,
            "solution" => cwe_rec }.compact
        end

        private

        def cwe(issue)
          "CWE-#{issue['finding_details']['cwe'].fetch('id')}" if issue["finding_details"]["cwe"]
        end

        def cve(issue)
          issue["finding_details"]["cve"]&.fetch("name")&.strip
        end

        def extract_additional_information(issue, recommendation = nil)
          scanner_score = issue["finding_details"].fetch("severity")
          additional_information = {
            "issue_id" => issue["issue_id"],
            "scan_type" => issue.fetch("scan_type"),
            "description" => issue.fetch("description"),
            "recommendation" => recommendation,
            "violates_policy" => issue.fetch("violates_policy"),
            "severity" => scanner_score
          }
          additional_information.merge!(issue["finding_details"])
          additional_information.merge!(issue["finding_status"])

          if (cwe = cwe(issue))
            cwe_name = issue["finding_details"]["cwe"].fetch("name")
            additional_information["cwe"] = "#{cwe} - #{cwe_name} - #{additional_information['cwe']['href']}"
          end
          additional_information["finding_category"] = "#{additional_information['finding_category']['id']} - #{additional_information['finding_category']['name']} - #{additional_information['finding_category']['href']}" if additional_information["finding_category"]

          additional_information.compact
        end
      end

      class Static < ScanType
        def extract_locator(issue, app_name)
          file = issue["finding_details"]["file_name"]
          { "file" => file, "external_id" => "[#{app_name}] - #{file}" }
        end
      end

      class Manual < ScanType
        def extract_locator(issue, app_name)
          file = issue["finding_details"]["location"]
          { "file" => file, "external_id" => "[#{app_name}] - #{file}" }
        end
      end

      class Dynamic < ScanType
        def extract_locator(issue, app_name)
          url = issue["finding_details"]["url"]
          { "url" => url, "external_id" => "[#{app_name}] - #{url}" }
        end
      end

      class SCA < ScanType
        def extract_locator(issue, app_name)
          file = issue["finding_details"]["component_filename"]
          { "file" => file, "external_id" => "[#{app_name}] - #{file}" }
        end

        def scanner_identifier(issue)
          cve(issue)
        end

        def vuln_def_name(issue)
          cve(issue)
        end

        def vuln_details(issue, _category_recommendations)
          JSON.pretty_generate(extract_additional_information(issue))
        end

        def extract_definition(issue, _cwe_recommendations)
          cwe = cwe(issue)
          cve = issue["finding_details"]["cve"].fetch("name").strip if issue["finding_details"]["cve"]
          cve_solution = issue["finding_details"]["cve"]["href"] if issue["finding_details"]["cve"]["href"]
          description = issue.fetch("description") if issue["description"]
          { "name" => cve,
            "scanner_type" => "veracode",
            "cwe_identifiers" => (cwe if cve.nil?),
            "cve_identifiers" => (cve if cve.include?("CVE")),
            "description" => description,
            "solution" => cve_solution }.compact
        end

        def finding_additional_fields(issue, _category_recommendations)
          extract_additional_information(issue)
        end
      end
    end
  end
end
