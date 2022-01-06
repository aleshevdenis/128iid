# frozen_string_literal: true

require_relative "mapper"
module Kenna
  module 128iid
    module WizV2
      class IssuesMapper < Mapper
        STATUS_MAP = {
          "open" => "open",
          "in_progress" => "open",
          "resolved" => "closed",
          "rejected" => "closed"
        }.freeze

        def name
          "Issue"
        end

        def plural_name
          "Issues"
        end

        def extract_asset(issue)
          {
            "external_id" => issue["entitySnapshot"]["resourceGroupExternalId"] || issue["entitySnapshot"]["providerId"],
            "owner" => issue["entitySnapshot"]["subscriptionId"],
            "tags" => extract_tags(issue)
          }.compact
        end

        def extract_tags(issue)
          tags = issue["entitySnapshot"]["tags"].map { |k, v| "#{k}:#{v}" }
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
      end
    end
  end
end
