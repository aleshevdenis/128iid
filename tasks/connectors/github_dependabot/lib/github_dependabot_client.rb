# frozen_string_literal: true

module Kenna
  module 128iid
    module GithubDependabotModule
      class GithubDependabotClient
        class ApiError < StandardError; end

        def initialize(organization_name, github_token)
          @github_token = github_token
          @organization_name = organization_name
          @endpoint = "https://api.github.com/graphql"
          @headers = { "content-type": "application/json", "Authorization": "Bearer #{github_token}" }
        end

        def security_advisory_response
          response = http_post(@endpoint, @headers, query(security_advisory_query, organization_name: @organization_name))
          raise ApiError, "Unable to retrieve data from GitHub GraphQL API, please check credentials" unless response

          response_hash = JSON.parse(response)
          raise ApiError, "Unable to retrieve data. GitHub GraphQL API returned the following errors:\n\n#{build_api_errors_string(response_hash['errors'])}" if response_hash["errors"]

          raise ApiError, "GitHub GraphQL API unrecognized response format." unless response_hash.dig("data", "organization", "repositories", "nodes")

          response_hash["data"]["organization"]["repositories"]["nodes"]
        end

        private

        def query(string, params = {})
          query = { query: string, variables: params }
          query.to_json
        end

        def security_advisory_query
          "query($organization_name: String!) {
          organization(login: $organization_name) {
            repositories(orderBy: {field: UPDATED_AT, direction: DESC}, first: 50) {
              nodes {
              name
                vulnerabilityAlerts(last: 50) {
                  nodes {
                    id
                    securityAdvisory {
                      description
                      cvss {
                        score
                      }
                      severity
                      identifiers {
                        type
                        value
                      }
                      summary
                      vulnerabilities(last: 50) {
                        nodes {
                          package {
                            name
                          }
                          severity
                          firstPatchedVersion {
                            identifier
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }"
        end

        def build_api_errors_string(errors)
          errors.map { |e| "[#{e['type']}] #{e['message']}" }.join("\n")
        end
      end
    end
  end
end
