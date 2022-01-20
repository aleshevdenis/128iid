# frozen_string_literal: true

module Kenna
  module 128iid
    module Sysdig
      class Mapper
        SCANNER_TYPE = "Sysdig"

        def self.import_type
          name.demodulize.gsub("Mapper", "")
        end

        def initialize(vuln, severity_mapping, vuln_definitions)
          @vuln = vuln
          @severity_mapping = severity_mapping
          @vuln_definitions = vuln_definitions
          @scan_data = vuln.fetch("scan_data")
        end

        def extract_vuln
          {
            "scanner_type" => SCANNER_TYPE,
            "scanner_identifier" => [scan_data["fullTag"] || scan_data["hostname"], vuln.fetch("package_name"), vuln.fetch("vuln"), self.class.import_type.upcase].join(":"),
            "vuln_def_name" => vuln.fetch("vuln"),
            "scanner_score" => severity_mapping.fetch(vuln.fetch("severity")),
            "details" => JSON.pretty_generate(extract_additional_fields)
          }.compact
        end

        def extract_definition
          definition = {
            "scanner_type" => SCANNER_TYPE,
            "name" => vuln.fetch("vuln"),
            "description" => vuln_definitions[vuln.fetch("vuln")]&.fetch("description")
          }
          definition["cwe_identifiers"] = vuln["vuln"] if vuln["vuln"].start_with?("CWE")
          definition["cve_identifiers"] = vuln["vuln"] if vuln["vuln"].start_with?("CVE")
          definition["wasc_identifiers"] = vuln["vuln"] if vuln["vuln"].start_with?("WASC")

          definition.compact
        end

        private

        attr_reader :vuln, :severity_mapping, :vuln_definitions, :scan_data

        def extract_additional_fields
          {
            "Image Name" => vuln["fullTag"],
            "Registry" => scan_data["registry"],
            "Repository" => scan_data["repository"],
            "Package" => vuln["package"],
            "Package Name" => vuln["package_name"],
            "Package Version" => vuln["package_version"],
            "Package Path" => vuln["package_path"],
            "Package Type" => vuln["package_type"],
            "Fix" => vuln["fix"],
            "Disclosure Date" => (Time.at(vuln["disclosure_date"]) if vuln["disclosure_date"].present?),
            "Sysdig Severity" => vuln["severity"],
            "URL" => vuln["url"],
            "Policy Status" => scan_data["policyStatus"]
          }.compact
        end
      end
    end
  end
end
