# frozen_string_literal: true

module Kenna
  module 128iid
    module Edgescan
      class EdgescanDefinition
        attr_accessor :data

        def initialize(definition)
          @data = definition
        end

        def to_kenna_definition
          {
            "scanner_type" => scanner_type,
            "scanner_identifier" => data["id"],
            "name" => data["name"],
            "description" => data["description_src"],
            "solution" => data["remediation_src"],
            "cve_identifiers" => cves,
            "cwe_identifiers" => cves ? nil : cwes
          }.compact
        end

        private

        def scanner_type
          data["layer"] == 7 ? "EdgescanApp" : "EdgescanNet"
        end

        def cves
          data["cves"].empty? ? nil : data["cves"].join(",")
        end

        def cwes
          data["cwes"].empty? ? nil : data["cwes"].join(",")
        end
      end
    end
  end
end
