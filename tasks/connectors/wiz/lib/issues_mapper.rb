# frozen_string_literal: true

require_relative "mapper"
module Kenna
  module 128iid
    module Wiz
      class IssuesMapper < Mapper
        STATUS_MAP = {
          "open" => "open",
          "in_progress" => "open",
          "resolved" => "closed",
          "rejected" => "closed"
        }.freeze

        def initialize(external_id_attr = "providerId")
          super()
          @external_id_attr = external_id_attr
        end

        def name
          "Issue"
        end

        def plural_name
          "Issues"
        end

        def extract_asset(issue)
          {
            "external_id" => extract_external_id(issue),
            "owner" => issue["entitySnapshot"]["subscriptionExternalId"] || issue["entitySnapshot"]["subscriptionId"],
            "tags" => extract_tags(issue)
          }.compact
        end

        def extract_tags(issue)
          tags = (issue["entitySnapshot"]["tags"] || []).map { |k, v| "#{k}:#{v}" }
          tags << "WizEntityType:#{issue['entitySnapshot']['type']}" if issue["entitySnapshot"]["type"].present?
          tags << "Region:#{issue['entitySnapshot']['region']}" if issue["entitySnapshot"]["region"].present?
          tags << "CloudPlatform:#{issue['entitySnapshot']['cloudPlatform']}" if issue["entitySnapshot"]["cloudPlatform"].present?
        end

        def extract_vuln(issue)
          vuln = {
            "scanner_identifier" => issue["entitySnapshot"]["id"],
            "scanner_type" => SCANNER_TYPE,
            "vuln_def_name" => extract_vuln_def_name(issue),
            "scanner_score" => SEVERITY_MAP[issue["severity"].downcase],
            "status" => STATUS_MAP[issue["status"].downcase],
            "created_at" => issue["createdAt"],
            "last_seen_at" => issue["updatedAt"],
            "details" => extract_details(issue)
          }
          vuln["last_fixed_on"] = issue["updatedAt"] if vuln["status"] == "closed"
          vuln.compact
        end

        def extract_vuln_def_name(issue)
          issue["control"]["name"]
        end

        def extract_definition(issue)
          {
            "name" => extract_vuln_def_name(issue),
            "description" => extract_vuln_def_name(issue),
            "scanner_type" => SCANNER_TYPE
          }.compact
        end

        def extract_details(issue)
          details = {
            "Issue ID" => issue["id"],
            "Control" => issue["control"].except("query"),
            "Projects" => issue["projects"],
            "Entity Snapshot" => issue["entitySnapshot"].except("tags")
          }.compact
          JSON.pretty_generate(details)
        end

        private

        def extract_external_id(issue)
          if issue["entitySnapshot"][@external_id_attr].present?
            issue["entitySnapshot"][@external_id_attr]
          else
            issue["entitySnapshot"]["providerId"]
          end
        end
      end
    end
  end
end
